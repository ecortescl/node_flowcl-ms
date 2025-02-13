// index.js
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Configuración por defecto (puedes usar variables de entorno)
const DEFAULT_FLOW_API_URL = process.env.FLOW_API_URL || 'https://www.flow.cl/api';
const DEFAULT_API_KEY = process.env.API_KEY || 'TU_API_KEY';
const DEFAULT_SECRET_KEY = process.env.SECRET_KEY || 'TU_SECRET_KEY';

// ====================
// Configuración Swagger
// ====================
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Flow Payment Microservice API',
      version: '1.0.0',
      description:
        'API para integración con Flow. Permite crear órdenes de pago, recibir callbacks y redirigir al usuario. Las credenciales se envían de forma segura a través de headers (x-api-key y x-secret-key).',
    },
    servers: [
      {
        url: 'http://localhost:3000',
      },
    ],
    components: {
      securitySchemes: {
        ApiKeyAuth: {
          type: 'apiKey',
          in: 'header',
          name: 'x-api-key',
          description: 'Clave pública de la API',
        },
        SecretKeyAuth: {
          type: 'apiKey',
          in: 'header',
          name: 'x-secret-key',
          description: 'Clave secreta de la API',
        },
      },
      schemas: {
        PaymentResponse: {
          type: 'object',
          properties: {
            paymentLink: {
              type: 'string',
              description: 'URL final para redirigir al pagador.',
              example: 'https://www.flow.cl/app/web/pay.php?token=860E70A184DAED8CE346EFDA3700DA51C526695U'
            },
            flowOrder: {
              type: 'integer',
              example: 127832165
            }
          }
        },
        Error: {
          type: 'object',
          properties: {
            error: {
              type: 'string',
              example: 'Error al procesar la creación del pago.'
            }
          }
        }
      }
    },
    security: [
      { ApiKeyAuth: [] },
      { SecretKeyAuth: [] }
    ]
  },
  apis: ['./index.js'], // Se leerán los comentarios de este archivo.
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// ====================
// Funciones Auxiliares
// ====================

/**
 * Función para generar la firma HMAC-SHA256.
 * Se excluye la propiedad 's', se ordenan las claves alfabéticamente y se concatena key+value.
 */
function generateSignature(params, secretKey) {
  const keys = Object.keys(params)
    .filter((key) => key !== 's')
    .sort();
  let stringToSign = '';
  keys.forEach((key) => {
    stringToSign += key + String(params[key]);
  });
  console.log('String to sign:', stringToSign);
  return crypto.createHmac('sha256', secretKey).update(stringToSign).digest('hex');
}

/**
 * Función para consultar el estado del pago usando el endpoint /payment/getStatus de Flow.
 */
async function getPaymentStatus(token) {
  const params = {
    apiKey: DEFAULT_API_KEY, // Aquí se pueden usar las credenciales configuradas
    token: token,
  };
  params.s = generateSignature(params, DEFAULT_SECRET_KEY);
  const url = `${DEFAULT_FLOW_API_URL}/payment/getStatus`;
  try {
    const response = await axios.get(url, { params });
    return response.data;
  } catch (error) {
    console.error('Error en getPaymentStatus:', error.message);
    if (error.response) {
      console.error('Status:', error.response.status);
      console.error('Data:', error.response.data);
    }
    throw error;
  }
}

// ====================
// Endpoints de la API
// ====================

/**
 * @swagger
 * /create-payment:
 *   post:
 *     security:
 *       - ApiKeyAuth: []
 *       - SecretKeyAuth: []
 *     summary: Crear orden de pago en Flow.
 *     description: >
 *       Crea una orden de pago en Flow. Se deben enviar los parámetros obligatorios (commerceOrder, subject, currency, amount, email, urlConfirmation y urlReturn) en el body.
 *       Las credenciales se obtienen de los headers: x-api-key y x-secret-key (si no se envían se usan los valores por defecto).
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               commerceOrder:
 *                 type: string
 *                 example: "orden123"
 *               subject:
 *                 type: string
 *                 example: "Compra de producto X"
 *               currency:
 *                 type: string
 *                 example: "CLP"
 *               amount:
 *                 type: number
 *                 example: 15000
 *               email:
 *                 type: string
 *                 example: "cliente@ejemplo.com"
 *               urlConfirmation:
 *                 type: string
 *                 example: "https://tuservidor.com/callback"
 *               urlReturn:
 *                 type: string
 *                 example: "https://tuservidor.com/retorno"
 *               optional:
 *                 type: string
 *                 example: "{}"
 *               timeout:
 *                 type: number
 *                 example: 300
 *               merchantId:
 *                 type: string
 *                 example: "MERC123"
 *               payment_currency:
 *                 type: string
 *                 example: "CLP"
 *     responses:
 *       '200':
 *         description: Orden de pago creada exitosamente.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/PaymentResponse'
 *       '500':
 *         description: Error al crear la orden de pago.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.post('/create-payment', async (req, res) => {
  try {
    // Se leen las credenciales desde los headers, de lo contrario se usan las predeterminadas.
    const key = req.headers['x-api-key'] || DEFAULT_API_KEY;
    const secret = req.headers['x-secret-key'] || DEFAULT_SECRET_KEY;

    const {
      commerceOrder,
      subject,
      currency,
      amount,
      email,
      urlConfirmation,
      urlReturn,
      optional,
      timeout,
      merchantId,
      payment_currency,
    } = req.body;

    let params = {
      apiKey: key,
      commerceOrder,
      subject,
      currency,
      amount,
      email,
      urlConfirmation,
      urlReturn,
      optional,
      timeout,
      merchantId,
      payment_currency,
    };

    Object.keys(params).forEach((k) => {
      if (params[k] === undefined) delete params[k];
    });

    params.s = generateSignature(params, secret);

    const flowUrl = `${DEFAULT_FLOW_API_URL}/payment/create`;
    console.log('Llamando a Flow API:', flowUrl);
    console.log('Parámetros enviados:', params);

    const formData = new URLSearchParams(params);
    const response = await axios.post(flowUrl, formData.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });
    console.log('Respuesta de Flow:', response.data);
    const paymentLink = `${response.data.url}?token=${response.data.token}`;
    res.json({ paymentLink, flowOrder: response.data.flowOrder });
  } catch (error) {
    console.error('Error al crear el pago:', error.message);
    if (error.response) {
      console.error('Status:', error.response.status);
      console.error('Data:', error.response.data);
    }
    res.status(500).json({ error: 'Error al procesar la creación del pago.' });
  }
});

/**
 * @swagger
 * /payment/confirmation:
 *   post:
 *     security:
 *       - ApiKeyAuth: []
 *       - SecretKeyAuth: []
 *     summary: Callback de confirmación de pago.
 *     description: >
 *       Endpoint llamado por Flow (urlConfirmation) vía POST con el token del pago.
 *       Se consulta el estado del pago usando /payment/getStatus.
 *     requestBody:
 *       required: true
 *       content:
 *         application/x-www-form-urlencoded:
 *           schema:
 *             type: object
 *             properties:
 *               token:
 *                 type: string
 *                 example: "860E70A184DAED8CE346EFDA3700DA51C526695U"
 *     responses:
 *       '200':
 *         description: Confirmación recibida correctamente.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "OK"
 *       '500':
 *         description: Error al procesar el callback.
 */
app.post('/payment/confirmation', async (req, res) => {
  const token = req.body.token;
  console.log('Callback de confirmation recibido con token:', token);
  try {
    const statusData = await getPaymentStatus(token);
    console.log('Estado del pago en confirmation:', statusData);
    // Aquí podrías actualizar tu base de datos con el estado del pago.
    res.status(200).send('OK');
  } catch (error) {
    console.error('Error en confirmation:', error.message);
    res.status(500).send('Error');
  }
});

/**
 * @swagger
 * /payment/success:
 *   get:
 *     security:
 *       - ApiKeyAuth: []
 *       - SecretKeyAuth: []
 *     summary: Redirección de pago exitoso.
 *     description: >
 *       Endpoint para redirigir al usuario en caso de pago exitoso.
 *       Se recibe el token en la query y se consulta el estado del pago.
 *     parameters:
 *       - in: query
 *         name: token
 *         required: true
 *         schema:
 *           type: string
 *         description: Token del pago.
 *     responses:
 *       '200':
 *         description: Página HTML de éxito.
 *         content:
 *           text/html:
 *             schema:
 *               type: string
 *               example: "<h1>Pago Exitoso</h1><p>Orden de Flow: 127832165</p><p>Estado: 2</p><p>Monto: 15000</p><p>Gracias por su compra.</p>"
 *       '500':
 *         description: Error al verificar el pago.
 */
app.get('/payment/success', async (req, res) => {
  const token = req.query.token;
  console.log('Redirección de éxito con token:', token);
  try {
    const statusData = await getPaymentStatus(token);
    console.log('Estado del pago en success:', statusData);
    res.send(`
      <h1>Pago Exitoso</h1>
      <p>Orden de Flow: ${statusData.flowOrder}</p>
      <p>Estado: ${statusData.status}</p>
      <p>Monto: ${statusData.amount}</p>
      <p>Gracias por su compra.</p>
    `);
  } catch (error) {
    res.status(500).send('Error al verificar el estado del pago.');
  }
});

/**
 * @swagger
 * /payment/cancel:
 *   get:
 *     security:
 *       - ApiKeyAuth: []
 *       - SecretKeyAuth: []
 *     summary: Redirección de pago cancelado.
 *     description: Endpoint para redirigir al usuario cuando el pago es cancelado.
 *     responses:
 *       '200':
 *         description: Página HTML de cancelación.
 *         content:
 *           text/html:
 *             schema:
 *               type: string
 *               example: "<h1>Pago Cancelado</h1><p>El pago fue cancelado. Intenta nuevamente si lo deseas.</p>"
 */
app.get('/payment/cancel', (req, res) => {
  console.log('Redirección de cancelación recibida:', req.query);
  res.send(`
    <h1>Pago Cancelado</h1>
    <p>El pago fue cancelado. Si lo deseas, puedes intentar realizarlo nuevamente.</p>
  `);
});

/**
 * @swagger
 * /payment/regenerate:
 *   post:
 *     security:
 *       - ApiKeyAuth: []
 *       - SecretKeyAuth: []
 *     summary: Regenerar orden de pago.
 *     description: >
 *       Permite reintentar la creación de una orden de pago utilizando la misma lógica que en /create-payment.
 *       Las credenciales se obtienen de los headers.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               commerceOrder:
 *                 type: string
 *                 example: "orden123"
 *               subject:
 *                 type: string
 *                 example: "Compra de producto X"
 *               currency:
 *                 type: string
 *                 example: "CLP"
 *               amount:
 *                 type: number
 *                 example: 15000
 *               email:
 *                 type: string
 *                 example: "cliente@ejemplo.com"
 *               urlConfirmation:
 *                 type: string
 *                 example: "https://tuservidor.com/callback"
 *               urlReturn:
 *                 type: string
 *                 example: "https://tuservidor.com/retorno"
 *     responses:
 *       '200':
 *         description: Orden de pago regenerada exitosamente.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/PaymentResponse'
 *       '500':
 *         description: Error al regenerar la orden de pago.
 */
app.post('/payment/regenerate', async (req, res) => {
  try {
    const {
      commerceOrder,
      subject,
      currency,
      amount,
      email,
      urlConfirmation,
      urlReturn,
      optional,
      timeout,
      merchantId,
      payment_currency,
    } = req.body;

    // Las credenciales se leen de los headers
    const key = req.headers['x-api-key'] || DEFAULT_API_KEY;
    const secret = req.headers['x-secret-key'] || DEFAULT_SECRET_KEY;

    let params = {
      apiKey: key,
      commerceOrder,
      subject,
      currency,
      amount,
      email,
      urlConfirmation,
      urlReturn,
      optional,
      timeout,
      merchantId,
      payment_currency,
    };

    Object.keys(params).forEach((k) => {
      if (params[k] === undefined) delete params[k];
    });

    params.s = generateSignature(params, secret);
    const flowUrl = `${DEFAULT_FLOW_API_URL}/payment/create`;
    console.log('Regenerando pago, llamando a Flow API:', flowUrl);
    console.log('Parámetros enviados:', params);

    const formData = new URLSearchParams(params);
    const response = await axios.post(flowUrl, formData.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });
    console.log('Respuesta de Flow en regenerate:', response.data);
    const paymentLink = `${response.data.url}?token=${response.data.token}`;
    res.json({ paymentLink, flowOrder: response.data.flowOrder });
  } catch (error) {
    console.error('Error al regenerar el pago:', error.message);
    if (error.response) {
      console.error('Status:', error.response.status);
      console.error('Data:', error.response.data);
    }
    res.status(500).json({ error: 'Error al regenerar el pago.' });
  }
});

// Inicia el servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Microservicio de Flow corriendo en el puerto ${PORT}`);
});
