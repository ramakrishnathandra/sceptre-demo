import logging
import os
from troposphere import Parameter
from troposphere import Template, Tags
from troposphere.ec2 import SecurityGroup
from pstesdictonary import PstesDictonary
from troposphere.ecs import Cluster, TaskDefinition, Service
from troposphere import FindInMap, Join, Ref, Tags
from troposphere import ec2
from troposphere import ecs
import troposphere.elasticloadbalancingv2 as elb
from troposphere.autoscaling import LaunchConfiguration
from troposphere import Base64, Join
from troposphere import iam
from troposphere.iam import Role, InstanceProfile, ManagedPolicy
from troposphere.iam import Policy as tPolicy
from awacs.aws import Allow, Statement, Principal, Policy
from awacs.sts import AssumeRole

tags = {
    "tr:environment-type": "DEVELOPMENT",
    "tr:resource-owner": "ramakrishna_thandra@epam.com",
}


class HackParameters(PstesDictonary):      
    def __init__(self):
        super(HackParameters, self).__init__()

        self.key_name = Parameter(
            "KeyName",
            Description="Name of an existing EC2 KeyPair to enable SSH access to the ECS instances",
            Type="AWS::EC2::KeyPair::KeyName"
        )

        self.vpc_id = Parameter(
            "VpcId",
            Description="Select a VPC that allows instances access to the Internet.",
            Type="AWS::EC2::VPC::Id"
        )

        self.subnet_id = Parameter(
            "SubnetId",
            Description="Select at two subnets in your selected VPC",
            Type="List<AWS::EC2::Subnet::Id>"
        )

        self.hack_instanceType = Parameter(
            "InstanceType",
            Description="EC2 instance type",
            Type="String",
            AllowedValues=[
                "t2.medium","t2.micro","t2.xlarge","t2.2xlarge","m1.small","m1.medium",
                "m1.large","m1.xlarge","m2.xlarge","m2.2xlarge","m2.4xlarge","m3.medium",
                "m3.large","m3.xlarge","m3.2xlarge","c1.medium","c1.xlarge","c3.large",
                "c3.xlarge","c3.2xlarge","c3.4xlarge", "c3.8xlarge","r3.large", "r3.xlarge",
                "r3.2xlarge","r3.4xlarge","r3.8xlarge","g2.2xlarge","i2.xlarge","i2.2xlarge",
                "i2.4xlarge","i2.8xlarge","hi1.4xlarge","hs1.8xlarge","cr1.8xlarge",
                "cc2.8xlarge","cg1.4xlarge"
            ],
            Default="t2.micro"
        )

        self.desired_capacity = Parameter(
            "DesiredCapacity",
            Description="Number of instances to launch in your ECS cluster",
            Type="Number",
            Default=1
        )

        self.max_size = Parameter(
            "MaxSize",
            Description="Maximum number of instances that can be launched in your ECS cluster",
            Type="Number",
            Default=1
        )

class HackMappings:
    def __init__(self):
        self.hackmappings = {
            "AWSRegionToAMI": {
                "us-east-1": {
                    "AMIID": "ami-0d09143c6fc181fe3"
                },
                "us-east-2": {
                    "AMIID": "ami-446f3521"
                }     
            }              
        }

class HackECSCluster(PstesDictonary):
    def __init__(self):
        super(HackECSCluster, self).__init__()

        self.hack_ecs_cluster = Cluster(
            "ECSCluster"
        )
        
class HackSecurityGroups(PstesDictonary):
    def __init__(self, hackparameters):
        super(HackSecurityGroups, self).__init__()
        self.cluster_security_group = ec2.SecurityGroup(
            "ClusterSecurityGroup",
            GroupDescription="ECS Security Group",
            VpcId=Ref(hackparameters.vpc_id)
        )

class HackSGConstant():
    def __init__(self,hackSg):
        self.hacksgdict = {
            "EcsSecurityGroupHTTPinbound" : {
                "ingressName" : "EcsSecurityGroupHTTPinbound",
                "fromPort":80,
                "toPort":80,
                "cidrip": "0.0.0.0/0"
            },
            "EcsSecurityGroupSSHinbound" : {
                "ingressName" : "EcsSecurityGroupSSHinbound",
                "fromPort":22,
                "toPort":22,
                "cidrip":"0.0.0.0/0"
            },
            "EcsSecurityGroupALBports" : {
                "ingressName" : "EcsSecurityGroupALBports",
                "fromPort":31000,
                "toPort":61000,
                "SourceSecurityGroupId": ""
            }
        }

class HackSecurityGroupsIngress(PstesDictonary):
    def __init__(self, securitygroups, ingressname, ingressvalue):
        """
        :type securitygroups SecurityGroups
        :type int fromPort
        :type int toPort
        :type string groupId
        """
        super(HackSecurityGroupsIngress, self).__init__()
        self.ingres_es_security_group = ec2.SecurityGroupIngress(
            ingressname,
            GroupId=Ref(securitygroups.cluster_security_group),
            IpProtocol="tcp",
            FromPort=ingressvalue["fromPort"],
            ToPort=ingressvalue["toPort"]            
        )

        if "SourceSecurityGroupId" in ingressvalue:
            self.ingres_es_security_group.SourceSecurityGroupId = Ref(securitygroups.cluster_security_group)
        else:
            self.ingres_es_security_group.CidrIp = ingressvalue["cidrip"]


class HackApplicationLoadBalancer(PstesDictonary):
    def __init__(self, hackparameters):
        super(HackApplicationLoadBalancer, self).__init__()
        self.load_balancer = elb.LoadBalancer(
            "ApplicationElasticLB",
            Name="ApplicationElasticLB",
            Scheme="internet-facing",
            Subnets=Ref(hackparameters.subnet_id)
        )

class HackTargetGroup(PstesDictonary):
    def __init__(self, hackparameters):
        super(HackTargetGroup, self).__init__()
        self.target_group = elb.TargetGroup(
            "ECSTG",
            HealthCheckIntervalSeconds="10",
            HealthCheckProtocol="HTTP",
            HealthCheckTimeoutSeconds="5",
            HealthyThresholdCount="2",
            Name="ECSTG",
            Port=80,
            HealthCheckPath="/",
            Protocol="HTTP",
            UnhealthyThresholdCount="2",
            VpcId=Ref(hackparameters.vpc_id)
        )

class HackListenerRule(PstesDictonary):
    def __init__(self, hackparameters, hacklistner,targetgroup):
        super(HackListenerRule, self).__init__()
        self.listner_rule = elb.ListenerRule(
            "ECSALBListenerRule",
            ListenerArn=Ref(hacklistner.app_listner),
            Conditions=[
                elb.Condition(
                    Field="path-pattern",
                    Values=["/"]
                )
            ],
            Actions=[
                elb.Action(
                    Type="forward",
                    TargetGroupArn=Ref(targetgroup.target_group)
                )
            ],
            Priority="1"
        )

class  HackApplicationListener(PstesDictonary):
    def __init__(self, hackparameters,appelb, targetgroup):
        super(HackApplicationListener, self).__init__()
        self.app_listner = elb.Listener(
            "ALBListener",
            Port="80",
            Protocol="HTTP",
            LoadBalancerArn=Ref(appelb.load_balancer),
            DefaultActions=[
                elb.Action(
                    Type="forward",
                    TargetGroupArn=Ref(targetgroup.target_group)
                )
            ]
        )

class HackAutoScalingGroup(PstesDictonary):
    def __init__(self, hackparameters,appelb, targetgroup):
        super(HackAutoScalingGroup, self).__init__()
        self.auto_scaling_group = elb.Listener(
            "ECSAutoScalingGroup",
            DesiredCapacity=Ref(hackparameters.desired_capacity),
            MinSize='1',
            MaxSize=Ref(hackparameters.max_size),
            VPCZoneIdentifier=Ref(hackparameters.subnet_id),
            LaunchConfigurationName=Ref('ContainerInstances'),
        )

class HackTaskDefination(PstesDictonary):
    def __init__(self):
        super(HackTaskDefination, self).__init__()
        self.hack_ecs_cluster = TaskDefinition(
            "taskdefinition",
            Family = Join(
                "",
                [
                    Ref("AWS::StackName"),
                    "-ecs-demo-app"
                ]
            ),
            ContainerDefinitions = [
                ecs.ContainerDefinition(
                    Name = "hackathon-app",
                    Cpu = 10,
                    Essential= 'true',
                    Image= "ramareddymca/docker-test:latest",
                    Memory= '300',
                    LogConfiguration = ecs.LogConfiguration(
                        LogDriver= "awslogs",
                        Options={
                            "awslogs-group" : Ref('CloudwatchLogsGroup'),
                            "awslogs-region" : Ref('AWS::Region'),
                            "awslogs-stream-prefix" : Ref('ecs-demo-app')
                        }
                    ),
                    PortMappings = [
                        ecs.PortMapping(
                            ContainerPort = 80
                        )
                    ]
                )
            ]
        )

class HackService(PstesDictonary):
    def __init__(self):
        super(HackService, self).__init__()
        self.hack_ecs_service = Service(
            "service",
            Cluster = Ref("ECSCluster"),
            DesiredCount = 1,
            LoadBalancers = [
                ecs.LoadBalancer(
                    ContainerName = "hackathon-app",
                    ContainerPort = 80,
                    TargetGroupArn = Ref("ECSTG")
                )            
            ],
            Role = Ref('ECSServiceRole'),
            TaskDefinition = Ref('taskdefinition')
        )


class HackIam(PstesDictonary):
    def __init__(self):
        super(HackIam, self).__init__()

        self.ecs_service_role = iam.Role(
            "ECSServiceRole",
            AssumeRolePolicyDocument=Policy(
                Statement=[
                    Statement(
                        Effect=Allow,
                        Action=[AssumeRole],
                        Principal=Principal(
                            "Service", [
                                "ecs.amazonaws.com"
                            ]
                        )
                    )
                ],
                Version="2012-10-17"
            ),
            Path="/",
            Policies=[
                tPolicy(
                    PolicyName="ecs-service",
                    PolicyDocument={
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "elasticloadbalancing:DeregisterInstancesFromLoadBalancer",
                                    "elasticloadbalancing:DeregisterTargets",
                                    "elasticloadbalancing:Describe*",
                                    "elasticloadbalancing:RegisterInstancesWithLoadBalancer",
                                    "elasticloadbalancing:RegisterTargets",
                                    "ec2:Describe*",
                                    "ec2:AuthorizeSecurityGroupIngress"
                                ],
                                "Resource": "*"
                            }
                        ]
                    }
                )
            ]
        )

        self.ec2_role = iam.Role(
            "EC2Role",
            AssumeRolePolicyDocument=Policy(
                Statement=[
                    Statement(
                        Effect=Allow,
                        Action=[AssumeRole],
                        Principal=Principal(
                            "Service", [
                                "ec2.amazonaws.com"
                            ]
                        )
                    )
                ],
                Version="2012-10-17"
            ),
            Path="/",
            Policies=[
                tPolicy(
                    PolicyName="ecs-service",
                    PolicyDocument={
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "ecs:CreateCluster",
                                    "ecs:DeregisterContainerInstance",
                                    "ecs:DiscoverPollEndpoint",
                                    "ecs:Poll",
                                    "ecs:RegisterContainerInstance",
                                    "ecs:StartTelemetrySession",
                                    "ecs:Submit*",
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents"
                                ],
                                "Resource": "*"
                            }
                        ]
                    }
                )
            ]
        )

        self.ec2_autoscaling = iam.Role(
            "AutoscalingRole",
            AssumeRolePolicyDocument=Policy(
                Statement=[
                    Statement(
                        Effect=Allow,
                        Action=[AssumeRole],
                        Principal=Principal(
                            "Service", [
                                "application-autoscaling.amazonaws.com"
                            ]
                        )
                    )
                ],
                Version="2012-10-17"
            ),
            Path="/",
            Policies=[
                tPolicy(
                    PolicyName="ecs-service",
                    PolicyDocument={
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "application-autoscaling:*",
                                    "cloudwatch:DescribeAlarms",
                                    "cloudwatch:PutMetricAlarm",
                                    "ecs:DescribeServices",
                                    "ecs:UpdateService"
                                ],
                                "Resource": "*"
                            }
                        ]
                    }
                )
            ]
        )

        self.iam_instanceprofile = iam.InstanceProfile(
            "EC2InstanceProfile",
            Roles=[
                Ref(self.ec2_role)
            ]
        )

class HackthonTemplate():
    def __init__(self):
        logging.debug('Hackthon Cloudformation generator')

    def cfn_template(self):
        template = Template()
        template.set_version("2010-09-09")
        template.set_description("CloudFormation template to create any number of Hackathon ecs nodes")
        
        hackparameters = HackParameters()
        for param in  hackparameters.values():
            template.add_parameter(param)
            
        for key, value in HackMappings().hackmappings.items():
            template.add_mapping(key, value)
            
        hackECSCluster = HackECSCluster()
        for res in hackECSCluster.values():
            template.add_resource(res)
            
        hackSg = HackSecurityGroups(hackparameters)
        for res in hackSg.values():
            template.add_resource(res)
            
        for ingress_name, ingress_value in HackSGConstant(hackSg).hacksgdict.items():
            sgIngress = HackSecurityGroupsIngress(
                securitygroups=hackSg,
                ingressname=ingress_name,
                ingressvalue=ingress_value
            )
            for res in sgIngress.values():
                template.add_resource(res)
        
        appelb = HackApplicationLoadBalancer(hackparameters)
        for res in appelb.values():
            template.add_resource(res)
            
        targetgroup = HackTargetGroup(hackparameters)
        for res in targetgroup.values():
            template.add_resource(res)

        hacklistner = HackApplicationListener(hackparameters,appelb,targetgroup)
        for res in hacklistner.values():
            template.add_resource(res)
            
        hackListenerRule = HackListenerRule(hackparameters,hacklistner,targetgroup)
        for res in hackListenerRule.values():
            template.add_resource(res)


        ContainerInstances = template.add_resource(
            LaunchConfiguration(
                'ContainerInstances',
                UserData=Base64(
                    Join(
                        '',
                        [
                            '#!/bin/bash -xe\n',
                            'echo ECS_CLUSTER=${ECSCluster} >> /etc/ecs/ecs.config\n'
                            'yum install -y aws-cfn-bootstrap\n',
                            '/opt/aws/bin/cfn-signal -e $? ',
                            '         --stack ',
                            Ref('AWS::StackName'),
                            '         --resource ECSAutoScalingGroup ',
                            '         --region ',
                            Ref('AWS::Region'),
                            '\n'
                        ]
                    )
                ),
                ImageId=FindInMap(
                    "AWSRegionToAMI",
                    Ref("AWS::Region"),
                    "AMIID"
                ),
                KeyName=Ref(hackparameters.key_name),
                SecurityGroups=[
                    hackSg.cluster_security_group
                ],
                InstanceType=Ref(hackparameters.hack_instanceType)
            )
        )
        
        hackTaskDef = HackTaskDefination()
        for res in hackTaskDef.values():
            template.add_resource(res)
    
        hackService = HackService()
        for res in hackService.values():
            template.add_resource(res)

        hackiamRole = HackIam()
        for res in hackiamRole.values():
            template.add_resource(res)
            
        return template.to_yaml()


def main():
    hackTemplate = HackthonTemplate()
    template = hackTemplate.cfn_template()
    templatepath = os.path.join(os.getcwd(), "hackathon-aws.yaml".format())
    f = open(templatepath,"w+")
    f.write(template)
    f.close()
    

if __name__ == "__main__":    
    main()

#def sceptre_handler(sceptre_user_data):
#    hackTemplate = HackthonTemplate()
#    template = hackTemplate.cfn_template()    
#    return template