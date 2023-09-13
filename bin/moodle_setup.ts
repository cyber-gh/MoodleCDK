#!/usr/bin/env node
import cdk = require('aws-cdk-lib');
import { EcsMoodleStack } from '../lib/ecs-moodle-stack';
import { CloudFrontWAFWebAclStack } from '../lib/cloudfront-waf-web-acl-stack';

const app = new cdk.App();

const deploymentEnv = {
    account: "952076674422",
    region: "eu-west-1"
}

const deploymentEnvGlobal = {
    account: "952076674422",
    region: "us-east-1"
}


const cloudFrontWAFWebAclStack = new CloudFrontWAFWebAclStack(app, 'cloudfront-waf-web-acl-stack', {
    env: deploymentEnvGlobal
});



const ecsMoodleStack = new EcsMoodleStack(app, 'ecs-moodle-v4-stack', {
    env: deploymentEnv
});
ecsMoodleStack.addDependency(cloudFrontWAFWebAclStack);
