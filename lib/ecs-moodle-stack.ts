import * as ecs from 'aws-cdk-lib/aws-ecs';
import {ContainerImage} from 'aws-cdk-lib/aws-ecs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as rds from 'aws-cdk-lib/aws-rds';
import * as efs from 'aws-cdk-lib/aws-efs';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as elasticache from 'aws-cdk-lib/aws-elasticache';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import {Certificate, CertificateValidation, DnsValidatedCertificate} from 'aws-cdk-lib/aws-certificatemanager';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as cloudtrail from 'aws-cdk-lib/aws-cloudtrail';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as subscriptions from 'aws-cdk-lib/aws-sns-subscriptions';
import * as cdk from 'aws-cdk-lib';
import {RemovalPolicy} from 'aws-cdk-lib';
import {SSMParameterReader} from './ssm-parameter-reader';
import {Repository} from "aws-cdk-lib/aws-ecr";
import {ARecord, HostedZone, RecordTarget} from "aws-cdk-lib/aws-route53";
import {DockerImageAsset} from "aws-cdk-lib/aws-ecr-assets";
import {DockerImageName, ECRDeployment} from "cdk-ecr-deployment";
import {CloudFrontTarget} from "aws-cdk-lib/aws-route53-targets";

export interface EcsMoodleStackProps extends cdk.StackProps {
}

export class EcsMoodleStack extends cdk.Stack {
    // Local Variables
    private readonly MoodleDatabaseName = 'moodledb';
    private readonly MoodleDatabaseUsername = 'dbadmin';

    constructor(scope: cdk.App, id: string, props: EcsMoodleStackProps) {
        super(scope, id, props);

        // CloudTrail
        const trailBucket = new s3.Bucket(this, 'cloudtrail-bucket', {
            blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
            enforceSSL: true,
            encryption: s3.BucketEncryption.S3_MANAGED,
            removalPolicy: RemovalPolicy.DESTROY
        });
        const trail = new cloudtrail.Trail(this, 'cloudtrail-trail', {
            bucket: trailBucket
        });

        // VPC
        const vpc = new ec2.Vpc(this, 'moodle-vpc', {
            maxAzs: 2,
            flowLogs: {
                'flowlog-to-cloudwatch': {
                    trafficType: ec2.FlowLogTrafficType.ALL
                }
            },
            natGateways: 1
        });
        // Amazon ECS tasks hosted on Fargate using platform version 1.4.0 or later require both Amazon ECR VPC endpoints and the Amazon S3 gateway endpoints.
        // Reference: https://docs.aws.amazon.com/AmazonECR/latest/userguide/vpc-endpoints.html#ecr-setting-up-vpc-create
        const ecrVpcEndpoint = vpc.addInterfaceEndpoint('ecr-vpc-endpoint', {
            service: ec2.InterfaceVpcEndpointAwsService.ECR
        });
        const s3VpcEndpoint = vpc.addGatewayEndpoint('s3-vpc-endpoint', {
            service: ec2.GatewayVpcEndpointAwsService.S3
        });

        // ECS Cluster
        const cluster = new ecs.Cluster(this, 'ecs-cluster', {
            vpc: vpc,
            clusterName: 'moodle-ecs-cluster'
        });

        // RDS
        const moodleDb = new rds.DatabaseInstance(this, 'moodle-db', {
            engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_8_0_32}),
            vpc: vpc,
            vpcSubnets: {
                subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS
            },
            instanceType: new ec2.InstanceType("t3.micro"),
            allocatedStorage: 20,
            maxAllocatedStorage: 300,
            storageType: rds.StorageType.GP2,
            autoMinorVersionUpgrade: true,
            multiAz: true,
            databaseName: this.MoodleDatabaseName,
            credentials: rds.Credentials.fromGeneratedSecret(this.MoodleDatabaseUsername, { excludeCharacters: '(" %+~`#$&*()|[]{}:;<>?!\'/^-,@_=\\' }), // Punctuations are causing issue with Moodle connecting to the database
            backupRetention: cdk.Duration.days(1),
        });
        const rdsEventSubscriptionTopic = new sns.Topic(this, 'rds-event-subscription-topic', { });
        rdsEventSubscriptionTopic.addSubscription(new subscriptions.EmailSubscription("andrei.manolescu@xfleet.io"));
        const rdsEventSubscription = new rds.CfnEventSubscription(this, 'rds-event-subscription', {
            enabled: true,
            snsTopicArn: rdsEventSubscriptionTopic.topicArn,
            sourceType: 'db-instance',
            eventCategories: [ 'availability', 'configuration change', 'failure', 'maintenance', 'low storage']
        });

        const efsSecurityGroup = new ec2.SecurityGroup(this, 'EfsSecurityGroup', {
            vpc: vpc,  // Assuming you have a VPC defined as 'vpc'
            description: 'Security Group for EFS',
            allowAllOutbound: true   // Typically set to true, but adjust as needed
        });

        efsSecurityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(2049), 'Allow NFS traffic from within VPC');

        // EFS
        const moodleEfs = new efs.FileSystem(this, 'moodle-efs', {
            vpc: vpc,
            lifecyclePolicy: efs.LifecyclePolicy.AFTER_30_DAYS,
            outOfInfrequentAccessPolicy: efs.OutOfInfrequentAccessPolicy.AFTER_1_ACCESS,
            performanceMode: efs.PerformanceMode.GENERAL_PURPOSE,
            throughputMode: efs.ThroughputMode.ELASTIC,
            removalPolicy: cdk.RemovalPolicy.DESTROY,
            enableAutomaticBackups: false,
            securityGroup: efsSecurityGroup
        });
        const moodleEfsAccessPoint = moodleEfs.addAccessPoint('moodle-efs-access-point', {
            path: '/'
        });

        // ElastiCache Redis
        const redisSG = new ec2.SecurityGroup(this, 'moodle-redis-sg', {
            vpc: vpc
        });

        const redisSubnetGroup = new elasticache.CfnSubnetGroup(this, 'redis-subnet-group', {
            cacheSubnetGroupName: `${cdk.Names.uniqueId(this)}-redis-subnet-group`,
            description: 'Moodle Redis Subnet Group',
            subnetIds: vpc.selectSubnets({ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }).subnetIds
        });

        // const moodleRedis = new elasticache.CfnReplicationGroup(this, 'moodle-redis', {
        //     replicationGroupDescription: 'Moodle Redis',
        //     cacheNodeType: "cache.t3.micro",
        //     engine: 'redis',
        //     numCacheClusters: 2,
        //     multiAzEnabled: true,
        //     automaticFailoverEnabled: true,
        //     autoMinorVersionUpgrade: true,
        //     cacheSubnetGroupName: `${cdk.Names.uniqueId(this)}-redis-subnet-group`,
        //     securityGroupIds: [ redisSG.securityGroupId ],
        //     atRestEncryptionEnabled: true,
        // });
        // moodleRedis.addDependency(redisSubnetGroup);

        // Moodle ECS Task Definition
        const moodleTaskDefinition = new ecs.FargateTaskDefinition(this, 'moodle-task-def', {
            cpu: 512,
            memoryLimitMiB: 1024
        });
        moodleTaskDefinition.addToExecutionRolePolicy(iam.PolicyStatement.fromJson({
            "Effect": "Allow",
            "Action": [
                "ecr:GetAuthorizationToken",
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "*"
        }));

        // EFS Volume
        moodleTaskDefinition.addVolume({
            name: 'moodle',
            efsVolumeConfiguration: {
                fileSystemId: moodleEfs.fileSystemId,
                transitEncryption: "ENABLED",
                authorizationConfig: {
                    accessPointId: moodleEfsAccessPoint.accessPointId
                }
            }
        });

        const moodleEcrRepo = new Repository(this, 'moodle-ecr-repo', {
            repositoryName: 'moodle-ecr',
            removalPolicy: RemovalPolicy.DESTROY
        })

        const imageAsset = new DockerImageAsset(this, 'moodle-image-asset', {
            directory: 'resources',
        })

        const deployment = new ECRDeployment(this, 'moodle-ecr-deployment', {
            src: new DockerImageName(imageAsset.imageUri),
            dest: new DockerImageName(`${props.env?.account}.dkr.ecr.${props.env?.region}.amazonaws.com/${moodleEcrRepo.repositoryName}:latest`),
        })


        // Moodle container definition
        const moodlePasswordSecret = new secretsmanager.Secret(this, 'moodle-password-secret');
        const moodleContainerDefinition = moodleTaskDefinition.addContainer('moodle-container', {
            containerName: 'moodle',
            image: ContainerImage.fromEcrRepository(moodleEcrRepo),
            memoryLimitMiB: 1024,
            portMappings: [{ containerPort: 8080 }],
            stopTimeout: cdk.Duration.seconds(120),
            environment: {
                'MOODLE_DATABASE_TYPE': 'mysqli',
                'MOODLE_DATABASE_HOST': moodleDb.dbInstanceEndpointAddress,
                'MOODLE_DATABASE_PORT_NUMBER': moodleDb.dbInstanceEndpointPort,
                'MOODLE_DATABASE_NAME': this.MoodleDatabaseName,
                'MOODLE_DATABASE_USER': this.MoodleDatabaseUsername,
                'MOODLE_USERNAME': 'moodleadmin',
                'MOODLE_EMAIL': 'hello@example.com',
                'MOODLE_SITE_NAME': 'Scalable Moodle on ECS Fargate',
                'MOODLE_SKIP_BOOTSTRAP': 'no',
                'MOODLE_SKIP_INSTALL': 'no',
                'BITNAMI_DEBUG': 'true'
            },
            secrets: {
                'MOODLE_DATABASE_PASSWORD': ecs.Secret.fromSecretsManager(moodleDb.secret!, 'password'),
                'MOODLE_PASSWORD': ecs.Secret.fromSecretsManager(moodlePasswordSecret)
            },
            logging: ecs.LogDrivers.awsLogs({ streamPrefix: 'ecs-moodle' })
        });
        moodleContainerDefinition.addMountPoints({
            sourceVolume: 'moodle',
            containerPath: '/bitnami',
            readOnly: false
        });

        const moodleServiceSecurityGroup = new ec2.SecurityGroup(this, 'MoodleServiceSecurityGroup', {
            vpc: vpc,
            description: 'Security Group for Moodle ECS Service',
            allowAllOutbound: true
        });

        moodleServiceSecurityGroup.addEgressRule(efsSecurityGroup, ec2.Port.tcp(2049), 'Allow NFS traffic to EFS');
        moodleServiceSecurityGroup.addIngressRule(efsSecurityGroup, ec2.Port.tcp(2049), 'Allow NFS traffic to EFS');

        moodleTaskDefinition.addToTaskRolePolicy(new iam.PolicyStatement({
            effect: iam.Effect.ALLOW,
            actions: [
                "elasticfilesystem:ClientMount",
                "elasticfilesystem:ClientWrite",
                "elasticfilesystem:ClientRootAccess"
            ],
            resources: [moodleEfs.fileSystemArn]
        }));

        // Moodle ECS Service
        const moodleService = new ecs.FargateService(this, 'moodle-service', {
            serviceName: "moodle-service",
            cluster: cluster,
            taskDefinition: moodleTaskDefinition,
            desiredCount: 1,
            vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
            enableECSManagedTags: true,
            maxHealthyPercent: 200,
            minHealthyPercent: 50,
            healthCheckGracePeriod: cdk.Duration.seconds(30),
            circuitBreaker: { rollback: true },
            securityGroups: [ moodleServiceSecurityGroup ]
        });

        // Moodle ECS Service Task Auto Scaling
        const moodleServiceScaling = moodleService.autoScaleTaskCount({ minCapacity: 1, maxCapacity: 1 } );
        moodleServiceScaling.scaleOnCpuUtilization('cpu-scaling', {
            targetUtilizationPercent: 50
        });

        moodleEfs.grantReadWrite(moodleService.taskDefinition.taskRole);
        moodleEfs.grantRootAccess(moodleService.taskDefinition.taskRole);

        // Allow access using Security Groups
        moodleDb.connections.allowDefaultPortFrom(moodleService, 'From Moodle ECS Service');
        moodleEfs.connections.allowDefaultPortFrom(moodleService, 'From Moodle ECS Service');
        redisSG.connections.allowFrom(moodleService, ec2.Port.tcp(6379), 'From Moodle ECS Service');

        // Moodle Load Balancer
        const alb = new elbv2.ApplicationLoadBalancer(this, 'moodle-alb', {
            loadBalancerName: 'moodle-ecs-alb',
            vpc: vpc,
            internetFacing: true,
            vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC }
        });
        const httpListener = alb.addListener('http-listener', {
            port: 80,
            protocol: elbv2.ApplicationProtocol.HTTP,
            open: true,
            defaultAction: elbv2.ListenerAction.redirect({ protocol: 'HTTPS', port: '443', permanent: true })
        });

        const domain = "axcg.app"
        const hostedZone = HostedZone.fromHostedZoneAttributes(this, "MoodleHostedZone",{
            hostedZoneId: 'Z08081041Z6HGYCJ8UTJ1',
            zoneName: domain
        })

        const albCertificate = new Certificate(this, "MoodleCertificate", {
            domainName: `moodle.${domain}`,
            validation: CertificateValidation.fromDns(hostedZone)
        })


        const httpsListener = alb.addListener('https-listener', {
            port: 443,
            protocol: elbv2.ApplicationProtocol.HTTPS,
            open: true,
            certificates: [ albCertificate ]
        });
        const targetGroup = httpsListener.addTargets('moodle-service-tg', {
            port: 8080,
            targets: [
                moodleService.loadBalancerTarget({
                    containerName: 'moodle',
                    containerPort: 8080,
                    protocol: ecs.Protocol.TCP
                })
            ],
            healthCheck: {
                timeout: cdk.Duration.seconds(100),
                interval: cdk.Duration.seconds(120),
                unhealthyThresholdCount: 10,
                healthyHttpCodes: '200-499'
            }
        });

        // CloudFront distribution
        const cfWafWebAclArnReader = new SSMParameterReader(this, 'cf-waf-web-acl-arn-ssm-param-reader', {
            parameterName: 'cf-waf-web-acl-arn',
            region: 'us-east-1'
        })

        const cloudFrontCertificate = new DnsValidatedCertificate(this, `Certificate-Cloudfront`, {
            region: "us-east-1",
            domainName: "moodle." + domain,
            hostedZone: hostedZone,
        })

        const cf = new cloudfront.Distribution(this, 'moodle-ecs-dist', {
            defaultBehavior: {
                viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                origin: new origins.LoadBalancerV2Origin(alb, {
                    readTimeout: cdk.Duration.seconds(10)
                }),
                cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
                allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
                originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER
            },
            domainNames: ["moodle." + domain],
            certificate: cloudFrontCertificate,
            webAclId: cfWafWebAclArnReader.getParameterValue()
        });

        const dnsRecord = new ARecord(this, 'moodle-ecs-dns-record', {
            recordName: "moodle." + domain,
            target: RecordTarget.fromAlias(new CloudFrontTarget(cf)),
            zone: hostedZone
        })

        // Outputs
        new cdk.CfnOutput(this, 'APPLICATION-LOAD-BALANCER-DNS-NAME', {
            value: alb.loadBalancerDnsName
        });
        new cdk.CfnOutput(this, 'CLOUDFRONT-DNS-NAME', {
            value: cf.distributionDomainName
        });
        new cdk.CfnOutput(this, 'MOODLE-USERNAME', {
            value: 'moodleadmin'
        });
        new cdk.CfnOutput(this, 'MOODLE-PASSWORD-SECRET-ARN', {
            value: moodlePasswordSecret.secretArn
        });
        // new cdk.CfnOutput(this, 'MOODLE-REDIS-PRIMARY-ENDPOINT-ADDRESS-AND-PORT', {
        //     value: `${moodleRedis.attrPrimaryEndPointAddress}:${moodleRedis.attrPrimaryEndPointPort}`
        // });
        new cdk.CfnOutput(this, 'ECS-CLUSTER-NAME', {
            value: cluster.clusterName
        });
        new cdk.CfnOutput(this, 'ECS-VPC-ID', {
            value: vpc.vpcId
        });
        new cdk.CfnOutput(this, 'MOODLE-SERVICE-NAME', {
            value: moodleService.serviceName
        });
        new cdk.CfnOutput(this, 'MOODLE-CLOUDFRONT-DIST-ID', {
            value: cf.distributionId
        });
    }
}
