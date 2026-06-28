import swaggerUi from 'swagger-ui-express'

export function createOpenApiDocument(port) {
  return {
    openapi: '3.0.0',
    info: {
      title: 'Create Neon Backend API',
      version: '1.0.0',
    },
    servers: [
      {
        url: `http://localhost:${port}`,
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },
    },
    paths: {
      '/health': {
        get: {
          summary: 'Health check',
          responses: {
            200: {
              description: 'Service is healthy',
            },
            500: {
              description: 'Service unavailable',
            },
          },
        },
      },
      '/api/auth/login': {
        post: {
          summary: 'Login',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    username: { type: 'string' },
                    password: { type: 'string' },
                  },
                  required: ['username', 'password'],
                },
              },
            },
          },
          responses: {
            200: {
              description: 'Login success',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      token: { type: 'string' },
                      user: {
                        type: 'object',
                        properties: {
                          id: { type: 'integer' },
                          username: { type: 'string' },
                          role: { type: 'string' },
                        },
                      },
                    },
                  },
                },
              },
            },
            400: {
              description: 'Missing credentials',
            },
            401: {
              description: 'Invalid credentials',
            },
            429: {
              description: 'Too many login attempts',
            },
          },
        },
      },
      '/api/auth/me': {
        get: {
          summary: 'Get the current authenticated user',
          security: [{ bearerAuth: [] }],
          responses: {
            200: {
              description: 'Authenticated user',
            },
            401: {
              description: 'Missing or invalid token',
            },
          },
        },
      },
      '/api/design-orders': {
        post: {
          summary: 'Save neon design order',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    text: { type: 'string' },
                    alignment: { type: 'string' },
                    fontId: { type: 'string' },
                    fontName: { type: 'string' },
                    colorId: { type: 'string' },
                    colorName: { type: 'string' },
                    widthCm: { type: 'integer' },
                    heightCm: { type: 'integer' },
                    locationId: { type: 'string' },
                    locationLabel: { type: 'string' },
                    quotedPrice: { type: 'integer' },
                  },
                  required: [
                    'text',
                    'alignment',
                    'fontId',
                    'fontName',
                    'colorId',
                    'colorName',
                    'widthCm',
                    'heightCm',
                    'locationId',
                    'locationLabel',
                    'quotedPrice',
                  ],
                },
              },
            },
          },
          responses: {
            201: {
              description: 'Design saved',
            },
            400: {
              description: 'Invalid payload',
            },
            500: {
              description: 'Save failed',
            },
          },
        },
      },
    },
  }
}

export function registerSwagger(app, port) {
  const openApiDocument = createOpenApiDocument(port)
  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(openApiDocument))
}
