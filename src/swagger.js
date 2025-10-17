const swaggerJSDoc = require('swagger-jsdoc');

const swaggerDefinition = {
  openapi: '3.0.0',
  info: {
    title: 'Authentication API',
    version: '1.0.0',
    description: 'API documentation for the authentication service with complete user management, email verification, and password reset functionality',
    contact: {
      name: 'API Support',
    },
  },
  servers: [
    {
      url: 'http://localhost:3000',
      description: 'Development server',
    },
  ],
  components: {
    securitySchemes: {
      bearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description: 'JWT token obtained from the login endpoint',
      },
    },
  },
  tags: [
    {
      name: 'Authentication',
      description: 'User authentication and account management endpoints',
    }
  ],
  security: [
    {
      bearerAuth: [],
    }
  ],
};

const options = {
  swaggerDefinition,
  apis: ['./src/routes/*.js'], // Path to the API routes
};

const swaggerSpec = swaggerJSDoc(options);

module.exports = swaggerSpec;