import {DeploymentState} from "aws-cdk/lib/util/work-graph-types";
import {App, Stack, StackProps} from "aws-cdk-lib";


export class MoodleBootstrapStack extends Stack {

    constructor(scope: App, id: string, props: StackProps) {
        super(scope, id, props);
    }
}
