// backend/server.js - VERSÃO ESTÁVEL PARA PRODUÇÃO
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { MongoClient, ObjectId } = require('mongodb');
const mercadopago = require('mercadopago');

const app = express();
const PORT = process.env.PORT || 8080;

// ========== VALIDAÇÃO DE VARIÁVEIS DE AMBIENTE ==========
const NODE_ENV = process.env.NODE_ENV || 'production';
const REQUIRED_ENV_VARS = ['MONGODB_URI', 'ADMIN_PASSWORD'];
const missingEnvVars = REQUIRED_ENV_VARS.filter(varName => !process.env[varName]);

if (missingEnvVars.length > 0) {
    console.error('❌ ERRO CRÍTICO - VARIÁVEIS DE AMBIENTE NÃO CONFIGURADAS:');
    missingEnvVars.forEach(varName => console.error(`   - ${varName}`));
    process.exit(1);
}

// ========== CONFIGURAÇÕES SEGURAS ==========
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = process.env.DB_NAME || 'bebcom_delivery';
const API_VERSION = '4.0.0-stable';

// ========== MERCADO PAGO ==========
const MERCADO_PAGO_ACCESS_TOKEN = process.env.MERCADO_PAGO_ACCESS_TOKEN;
const MERCADO_PAGO_PUBLIC_KEY = process.env.MERCADO_PAGO_PUBLIC_KEY;

if (MERCADO_PAGO_ACCESS_TOKEN) {
    mercadopago.configure({
        access_token: MERCADO_PAGO_ACCESS_TOKEN
    });
    console.log('✅ Mercado Pago SDK configurado');
}

// ========== RATE LIMITING ==========
const adminLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    skipSuccessfulRequests: true,
    message: {
        success: false,
        error: 'Muitas tentativas de admin. Aguarde 15 minutos.'
    }
});

const paymentLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 10,
    message: {
        success: false,
        error: 'Muitas tentativas de pagamento. Aguarde 5 minutos.'
    }
});

// ========== CORS ==========
app.use(cors({
    origin: true,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
        'Content-Type',
        'Authorization',
        'x-admin-password',
        'x-admin-key',
        'Cache-Control',
        'Accept'  // ✅ ÚNICA CORREÇÃO NECESSÁRIA
    ]
}));

app.options('*', cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ========== LOG DE INICIALIZAÇÃO ==========
console.log('='.repeat(70));
console.log('🍹 BEBCOM DELIVERY API');
console.log('='.repeat(70));
console.log(`📅 Inicialização: ${new Date().toISOString()}`);
console.log(`🌍 Ambiente: ${NODE_ENV}`);
console.log(`📦 Versão: ${API_VERSION}`);

// ========== HEALTH CHECKS ==========
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'healthy',
        service: 'BebCom Delivery API',
        version: API_VERSION,
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        node: process.version,
        environment: NODE_ENV,
        dbStatus: app.locals.isDBConnected ? 'connected' : 'disconnected',
        mercadopago: MERCADO_PAGO_ACCESS_TOKEN ? 'configured' : 'missing'
    });
});

app.get('/health/liveness', (req, res) => {
    res.status(200).json({ status: 'alive' });
});

app.get('/health/readiness', (req, res) => {
    const isReady = app.locals.isDBConnected !== false;
    res.status(isReady ? 200 : 503).json({
        status: isReady ? 'ready' : 'not_ready'
    });
});

// ========== ROTA DE CONFIGURAÇÃO PÚBLICA CORRIGIDA ==========
app.get('/api/config', (req, res) => {
    // ✅ FORÇA HTTPS em produção
    const protocol = req.headers['x-forwarded-proto'] || req.protocol;
    const host = req.get('host');
    const backendUrl = (protocol === 'https' || process.env.NODE_ENV === 'production') 
        ? `https://${host}` 
        : `${protocol}://${host}`;

    res.json({
        backendUrl: backendUrl,  // ✅ AGORA SEMPRE HTTPS
        whatsappNumber: process.env.WHATSAPP_NUMBER || '',
        mercadoPago: {
            publicKey: process.env.MERCADO_PAGO_PUBLIC_KEY || null,
            testMode: NODE_ENV !== 'production'
        },
        storeLocation: {
            lat: -22.35892,
            lng: -49.0987233,
            address: "R. José Henrique Ferraz, 18-10 - Centro, Bauru - SP"
        },
        deliveryRates: {
            baseFee: 5.00,
            perKm: 2.65,
            maxDistance: 15,
            minDistance: 0.5,
            freeDeliveryMin: 100.00
        },
        version: API_VERSION,
        environment: NODE_ENV
    });
});

// ========== ROTA RAIZ ==========
app.get('/', (req, res) => {
    res.json({
        success: true,
        service: 'BebCom Delivery API',
        version: API_VERSION,
        status: 'operational',
        endpoints: {
            health: '/health',
            config: '/api/config',
            products: '/api/product-availability',
            flavors: '/api/flavor-availability',
            payment: '/api/create-payment'
        }
    });
});

// ========== ROTA DE VERIFICAÇÃO ADMIN ==========
app.post('/api/admin/verify', adminLimiter, (req, res) => {
    const { password } = req.body;

    if (!password) {
        return res.status(400).json({
            success: false,
            error: 'Senha não fornecida'
        });
    }

    const currentYear = new Date().getFullYear();
    const expectedHash = crypto
        .createHash('sha256')
        .update(ADMIN_PASSWORD)
        .digest('hex');

    const hashWithSalt = crypto
        .createHash('sha256')
        .update(ADMIN_PASSWORD + 'bebcom_' + currentYear)
        .digest('hex');

    if (password === ADMIN_PASSWORD ||
        password === expectedHash ||
        password === hashWithSalt) {

        const token = crypto
            .createHash('sha256')
            .update(ADMIN_PASSWORD + Date.now() + crypto.randomBytes(16).toString('hex'))
            .digest('hex');

        return res.json({
            success: true,
            token: token,
            message: 'Autenticado com sucesso'
        });
    }

    return res.status(401).json({
        success: false,
        error: 'Senha administrativa incorreta'
    });
});

// ========== ENDPOINT DE PAGAMENTO MERCADO PAGO ==========
app.post('/api/create-payment', paymentLimiter, async (req, res) => {
    try {
        const {
            orderId,
            customer,
            items,
            total,
            deliveryFee,
            deliveryType,
            paymentMethod,
            address
        } = req.body;

        if (!items || !Array.isArray(items) || items.length === 0) {
            return res.status(400).json({
                success: false,
                error: 'Itens do pedido são obrigatórios'
            });
        }

        if (!customer || !customer.email) {
            return res.status(400).json({
                success: false,
                error: 'E-mail do cliente é obrigatório'
            });
        }

        if (!MERCADO_PAGO_ACCESS_TOKEN) {
            return res.status(503).json({
                success: false,
                error: 'Mercado Pago não configurado'
            });
        }

        // Formata itens
        const mpItems = items.map(item => ({
            title: item.title,
            description: item.description || item.title,
            quantity: Number(item.quantity),
            unit_price: Number(item.unit_price),
            currency_id: 'BRL'
        }));

        if (deliveryType === 'delivery' && deliveryFee > 0) {
            mpItems.push({
                title: 'Taxa de Entrega',
                description: 'Taxa de entrega',
                quantity: 1,
                unit_price: Number(deliveryFee),
                currency_id: 'BRL'
            });
        }

        // URLs de retorno
        const successUrl = `${req.headers.origin || 'https://bebcom.com.br'}/?status=approved&order_id=${orderId}`;
        const failureUrl = `${req.headers.origin || 'https://bebcom.com.br'}/?status=failure`;
        const pendingUrl = `${req.headers.origin || 'https://bebcom.com.br'}/?status=pending`;

        // Cria preferência
        const preference = {
            items: mpItems,
            payer: {
                name: customer.name,
                email: customer.email,
                phone: {
                    number: customer.phone.replace(/\D/g, '')
                }
            },
            external_reference: orderId,
            back_urls: {
                success: successUrl,
                failure: failureUrl,
                pending: pendingUrl
            },
            auto_return: 'approved',
            notification_url: `${req.protocol}://${req.get('host')}/api/webhooks/mercadopago`,
            statement_descriptor: 'BEBCOM DELIVERY'
        };

        const response = await mercadopago.preferences.create(preference);

        if (app.locals.db) {
            await app.locals.db.collection('orders').insertOne({
                orderId: orderId,
                preferenceId: response.body.id,
                customer: customer,
                items: items,
                total: total,
                deliveryFee: deliveryFee,
                deliveryType: deliveryType,
                address: address,
                status: 'pending',
                createdAt: new Date(),
                initPoint: response.body.init_point
            });
        }

        res.json({
            success: true,
            preferenceId: response.body.id,
            initPoint: response.body.init_point
        });

    } catch (error) {
        console.error('❌ Erro no pagamento:', error);
        res.status(500).json({
            success: false,
            error: 'Erro ao criar pagamento'
        });
    }
});

// ========== WEBHOOK DO MERCADO PAGO ==========
app.post('/api/webhooks/mercadopago', async (req, res) => {
    try {
        const { type, data } = req.body;
        console.log('📩 Webhook recebido:', { type, data });

        res.status(200).json({ received: true });

        if (type === 'payment' && data.id && app.locals.db) {
            await app.locals.db.collection('orders').updateOne(
                { preferenceId: data.id },
                {
                    $set: {
                        status: 'approved',
                        payment_id: data.id,
                        updatedAt: new Date()
                    }
                }
            );
        }

    } catch (error) {
        console.error('❌ Erro no webhook:', error);
        res.status(500).json({ error: 'Erro interno' });
    }
});

// ========== ROTAS DE DISPONIBILIDADE ==========
app.get('/api/product-availability', async (req, res) => {
    try {
        if (!app.locals.db) {
            return res.json({ success: true, productAvailability: {}, offline: true });
        }

        const productData = await app.locals.db.collection('products')
            .findOne({ type: 'availability' });

        res.json({
            success: true,
            productAvailability: productData?.data || {}
        });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Erro ao buscar produtos' });
    }
});

app.get('/api/flavor-availability', async (req, res) => {
    try {
        if (!app.locals.db) {
            return res.json({ success: true, flavorAvailability: {}, offline: true });
        }

        const flavorData = await app.locals.db.collection('flavors')
            .findOne({ type: 'availability' });

        res.json({
            success: true,
            flavorAvailability: flavorData?.data || {}
        });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Erro ao buscar sabores' });
    }
});

// ========== MIDDLEWARE DE AUTENTICAÇÃO ADMIN ==========
function authenticateAdmin(req, res, next) {
    const directPassword = req.body.password ||
        req.headers['x-admin-password'] ||
        req.query.adminPassword;

    const authHeader = req.headers['authorization'];
    const token = authHeader?.startsWith('Bearer ') ? authHeader.substring(7) : null;

    if (token && token.length === 64 && /^[a-f0-9]+$/i.test(token)) {
        return next();
    }

    if (directPassword && directPassword === ADMIN_PASSWORD) {
        return next();
    }

    return res.status(401).json({
        success: false,
        error: 'Senha ou token inválido'
    });
}

// ========== ROTAS ADMIN ==========
app.post('/api/admin/product-availability/bulk', adminLimiter, authenticateAdmin, async (req, res) => {
    try {
        if (!app.locals.db) {
            return res.status(503).json({ success: false, error: 'Banco de dados indisponível' });
        }

        const { productAvailability } = req.body;

        await app.locals.db.collection('products').updateOne(
            { type: 'availability' },
            { $set: { data: productAvailability, lastUpdated: new Date() } },
            { upsert: true }
        );

        res.json({ success: true, message: 'Produtos atualizados' });

    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/admin/flavor-availability/bulk', adminLimiter, authenticateAdmin, async (req, res) => {
    try {
        if (!app.locals.db) {
            return res.status(503).json({ success: false, error: 'Banco de dados indisponível' });
        }

        const { flavorAvailability } = req.body;

        await app.locals.db.collection('flavors').updateOne(
            { type: 'availability' },
            { $set: { data: flavorAvailability, lastUpdated: new Date() } },
            { upsert: true }
        );

        res.json({ success: true, message: 'Sabores atualizados' });

    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========== INICIALIZAÇÃO DO MONGODB ==========
async function initializeMongoDB() {
    try {
        if (!MONGODB_URI) {
            console.error('❌ MONGODB_URI não configurada');
            return;
        }

        console.log('🔌 Conectando ao MongoDB...');

        const client = new MongoClient(MONGODB_URI, {
            connectTimeoutMS: 10000,
            socketTimeoutMS: 45000
        });

        await client.connect();
        await client.db('admin').command({ ping: 1 });

        const db = client.db(DB_NAME);

        console.log('✅ MongoDB conectado!');
        console.log(`📊 Database: ${DB_NAME}`);

        app.locals.db = db;
        app.locals.mongoClient = client;
        app.locals.isDBConnected = true;

        // Cria collections se não existirem
        const collections = ['products', 'flavors', 'orders', 'admin_logs'];
        for (const name of collections) {
            try {
                await db.createCollection(name);
                console.log(`📦 Collection criada: ${name}`);
            } catch (e) {
                // Collection já existe
            }
        }

    } catch (error) {
        console.error('❌ Falha na conexão MongoDB:', error.message);
        app.locals.isDBConnected = false;
    }
}

// ========== GRACEFUL SHUTDOWN ==========
process.on('SIGTERM', () => {
    console.log('👋 Encerrando...');
    if (app.locals.mongoClient) {
        app.locals.mongoClient.close();
    }
    process.exit(0);
});

// ========== INICIAR SERVIDOR ==========
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Servidor rodando na porta ${PORT}`);
    console.log(`📡 Health: http://0.0.0.0:${PORT}/health`);
    console.log(`⚙️  Config: http://0.0.0.0:${PORT}/api/config`);
    console.log('='.repeat(70));

    setTimeout(initializeMongoDB, 1000);
});

module.exports = app;
