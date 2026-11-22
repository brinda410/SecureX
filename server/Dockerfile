# Use Node.js 22
FROM node:22-alpine

# Set working directory
WORKDIR /app

# Copy package files
COPY package.json package-lock.json ./

# Install production dependencies
RUN npm ci --omit=dev

# Copy backend application
COPY . .

# Set production environment
ENV NODE_ENV=production

# Backend port
EXPOSE 5000

# Start SecureX server
CMD ["npm", "start"]