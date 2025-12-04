#!/bin/bash
# Deployment script for AWS EC2

# Update system
sudo yum update -y

# Install Node.js 18
curl -fsSL https://rpm.nodesource.com/setup_18.x | sudo bash -
sudo yum install -y nodejs

# Install PM2 for process management
sudo npm install -g pm2

# Install Git
sudo yum install -y git

# Clone your repository
git clone https://github.com/capeparts1003-star/powersports-api.git
cd powersports-api

# Install dependencies
npm install

# Install PostgreSQL client
sudo yum install -y postgresql

# Create .env file (you'll need to edit this with real values)
cat > .env << EOL
NODE_ENV=production
PORT=4000
DATABASE_URL=postgresql://postgres:yourpassword@your-rds-endpoint:5432/powersports_db
JWT_SECRET=your-super-secure-jwt-secret-here
STRIPE_SECRET_KEY=sk_test_your_stripe_key
AWS_REGION=us-east-1
AWS_S3_BUCKET=your-bucket-name
EOL

# Run database migrations
npx prisma migrate deploy

# Start the application with PM2
pm2 start server.js --name "powersports-api"
pm2 startup
pm2 save

# Install and configure nginx (optional)
sudo yum install -y nginx
sudo systemctl start nginx
sudo systemctl enable nginx

echo "Deployment complete! Your API should be running on port 4000"
echo "Don't forget to:"
echo "1. Update your .env file with real database credentials"
echo "2. Configure your domain DNS to point to this server"
echo "3. Set up SSL certificate"