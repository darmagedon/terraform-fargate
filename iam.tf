resource "aws_iam_role" "ECSAutoScalingRole" {
  name = "ECSAutoScalingRole"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ecs.application-autoscaling.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

  tags = {
    Project = "Leapfrogger"
  }
}

resource "aws_iam_policy" "ECSAutoScalingPolicy" {
  name        = "ECSAutoScalingPolicy"
  description = "ECSAutoScalingPolicy"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ecs:DescribeServices",
                "ecs:UpdateService",
                "cloudwatch:PutMetricAlarm",
                "cloudwatch:DescribeAlarms",
                "cloudwatch:DeleteAlarms"
            ],
            "Resource": [
                "*"
            ]
        }
    ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "attach-auto-scaling" {
  role       = "${aws_iam_role.ECSAutoScalingRole.name}"
  policy_arn = "${aws_iam_policy.ECSAutoScalingPolicy.arn}"
}

resource "aws_iam_role" "ECSTasksExecutionRole" {
  name = "ECSTasksExecutionRole"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "ecs-tasks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

  tags = {
    Project = "Leapfrogger"
  }
}

resource "aws_iam_policy" "ECSTasksExecutionPolicy" {
  name        = "ECSTasksExecutionPolicy"
  description = "ECSTasksExecutionPolicy"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
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
        }
    ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "attach-tasks-execution" {
  role       = "${aws_iam_role.ECSTasksExecutionRole.name}"
  policy_arn = "${aws_iam_policy.ECSTasksExecutionPolicy.arn}"
}