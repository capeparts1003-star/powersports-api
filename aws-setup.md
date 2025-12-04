# AWS Free Tier Setup Guide

## Prerequisites
- AWS Account created
- AWS CLI installed
- Your domain name (optional for now)

## Step 1: Create EC2 Instance (Free Tier)
1. Go to EC2 Dashboard
2. Launch Instance
3. Choose: Amazon Linux 2 AMI (Free tier eligible)
4. Instance Type: t2.micro (Free tier eligible)
5. Configure Security Group:
   - SSH (port 22) - Your IP only
   - HTTP (port 80) - Anywhere
   - HTTPS (port 443) - Anywhere
   - Custom TCP (port 4000) - Anywhere (for API)

## Step 2: Create RDS Database (Free Tier)
1. Go to RDS Dashboard
2. Create Database
3. Choose: PostgreSQL
4. Template: Free tier
5. Instance: db.t2.micro
6. Storage: 20 GB (free tier limit)
7. Database name: powersports_db
8. Username: postgres
9. Password: [secure password]

## Step 3: Create S3 Bucket
1. Go to S3 Dashboard
2. Create bucket: powersports-images-[random-string]
3. Region: us-east-1 (cheapest)
4. Block all public access: OFF (for image serving)
5. Versioning: Disabled (save costs)

## Step 4: Environment Variables
Create .env file with:
```
NODE_ENV=production
PORT=4000
DATABASE_URL=postgresql://postgres:[password]@[rds-endpoint]:5432/powersports_db
JWT_SECRET=[generate-secure-secret]
STRIPE_SECRET_KEY=[your-stripe-key]
AWS_REGION=us-east-1
AWS_S3_BUCKET=powersports-images-[your-string]
```

## Estimated Monthly Cost: $0.50 (Route 53 only)