# INTENTIONALLY INSECURE demo for CloudGuard. Never deploy this.

variable "admin_cidr" {
  type = string
}

# Public bucket: public-read ACL, no Block Public Access, no versioning.
resource "aws_s3_bucket" "marketing_assets" {
  bucket = "acme-marketing-assets"
  acl    = "public-read"
}

# Hardened bucket, for contrast.
resource "aws_s3_bucket" "customer_data" {
  bucket = "acme-customer-data"
}

resource "aws_s3_bucket_public_access_block" "customer_data" {
  bucket                  = aws_s3_bucket.customer_data.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "customer_data" {
  bucket = aws_s3_bucket.customer_data.id
  versioning_configuration {
    status = "Enabled"
  }
}

# SSH and RDP open to the whole Internet.
resource "aws_security_group" "bastion" {
  name = "bastion"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port        = 3389
    to_port          = 3389
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }
}

# Everything open: the worst case.
resource "aws_security_group" "temp_debug" {
  name = "temp-debug"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# HTTPS to the world is fine. SSH comes from a variable, so CloudGuard cannot judge it
# and skips it instead of guessing. The separate rule below opens RDP.
resource "aws_security_group" "web_tier" {
  name = "web-tier"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }
}

resource "aws_security_group_rule" "web_rdp" {
  type              = "ingress"
  security_group_id = aws_security_group.web_tier.id
  from_port         = 3389
  to_port           = 3389
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
}

# A "temporary" admin policy that never got removed.
resource "aws_iam_policy" "ops_admin" {
  name = "ops-admin"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# Scoped correctly: this one must NOT be reported.
resource "aws_iam_role_policy" "reader" {
  name = "read-logs"
  role = "app"

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": ["logs:GetLogEvents"], "Resource": "*" }
  ]
}
POLICY
}
