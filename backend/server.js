// backend/server.js - VERSÃO PRODUÇÃO PARA AZURE (COMPLETO COM MERCADO PAGO)
const express = require('express');
const cors = require('cors');
const http = require('http');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { MercadoPagoConfig, Preference } = require('mercadopago'); // ✅ ADICIONADO

const app = express();
const PORT = process.env.PORT || 8080;

// ========== VALIDAÇÃO DE VARIÁVEIS CRÍTICAS ==========
const NODE_ENV = process.env.NODE_ENV || 'production';
const REQUIRED_ENV_VARS = ['MONGODB_URI', 'ADMIN_PASSWORD'];
const missingEnvVars = REQUIRED_ENV_VARS.filter(varName => !process.env[varName]);

if (missingEnvVars.length > 0) {
    console.error('='.repeat(70));
    console.error('❌ ERRO CRÍTICO - VARIÁVEIS DE AMBIENTE NÃO CONFIGURADAS:');
    missingEnvVars.forEach(varName => console.error(`   - ${varName}`));
    console.error('='.repeat(70));
    console.error('📌 Configure no Azure: Portal -> App Service -> Configuration');
    console.error('='.repeat(70));
    process.exit(1);
}

// ========== CONFIGURAÇÕES SEGURAS ==========
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = process.env.DB_NAME || 'bebcom_delivery';
const API_VERSION = '4.0.0-azure-mp'; // ✅ Versão atualizada

// ========== MERCADO PAGO ==========
const MERCADO_PAGO_ACCESS_TOKEN = process.env.MERCADO_PAGO_ACCESS_TOKEN;
const MERCADO_PAGO_PUBLIC_KEY = process.env.MERCADO_PAGO_PUBLIC_KEY;
const MERCADO_PAGO_WEBHOOK_SECRET = process.env.MERCADO_PAGO_WEBHOOK_SECRET;

// Inicializa cliente do Mercado Pago (se token disponível)
let mercadopagoClient = null;
if (MERCADO_PAGO_ACCESS_TOKEN) {
    try {
        const client = new MercadoPagoConfig({ 
            accessToken: MERCADO_PAGO_ACCESS_TOKEN,
            options: { timeout: 5000 }
        });
        mercadopagoClient = client;
        console.log('✅ Mercado Pago SDK inicializado');
    } catch (error) {
        console.error('❌ Erro ao inicializar Mercado Pago:', error.message);
    }
}

// ========== RATE LIMITING ==========
const adminLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    skipSuccessfulRequests: true,
    message: {
        success: false,
        error: 'Muitas tentativas de admin. Aguarde 15 minutos.'
    },
    standardHeaders: true,
    legacyHeaders: false
});

const paymentLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutos
    max: 10, // 10 tentativas de pagamento
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
        'X-Requested-With',
        'Accept',
        'x-meli-session-id' // Para Mercado Pago
    ]
}));

app.options('*', cors());

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ========== LOG DE INICIALIZAÇÃO ==========
console.log('='.repeat(70));
console.log('🍹 BEBCOM DELIVERY API - PRODUÇÃO AZURE');
console.log('='.repeat(70));
console.log(`📅 Inicialização: ${new Date().toISOString()}`);
console.log(`🌍 Ambiente: ${NODE_ENV}`);
console.log(`🔌 Porta: ${PORT}`);
console.log(`📦 Versão: ${API_VERSION}`);
console.log(`💳 Mercado Pago: ${MERCADO_PAGO_ACCESS_TOKEN ? '✅ Configurado' : '❌ Não configurado'}`);
console.log('='.repeat(70));

// ========== HEALTH CHECKS ==========
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'healthy',
        service: 'BebCom Delivery API',
        version: API_VERSION,
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        node: process.version,
        environment: NODE_ENV,
        dbStatus: app.locals.isDBConnected ? 'connected' : 'disconnected',
        mercadopago: MERCADO_PAGO_ACCESS_TOKEN ? 'configured' : 'missing'
    });
});

app.get('/health/liveness', (req, res) => {
    res.status(200).json({ status: 'alive', timestamp: new Date().toISOString() });
});

app.get('/health/readiness', (req, res) => {
    const isReady = app.locals.isDBConnected !== false;
    res.status(isReady ? 200 : 503).json({
        status: isReady ? 'ready' : 'not_ready',
        db: app.locals.isDBConnected ? 'connected' : 'disconnected',
        timestamp: new Date().toISOString()
    });
});

// ========== ROTA DE CONFIGURAÇÃO PÚBLICA ==========
app.get('/api/config', (req, res) => {
    res.json({
        backendUrl: `${req.protocol}://${req.get('host')}`,
        whatsappNumber: process.env.WHATSAPP_NUMBER || '',
        mercadoPago: {
            publicKey: MERCADO_PAGO_PUBLIC_KEY || null,
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
        environment: NODE_ENV,
        status: 'operational',
        timestamp: new Date().toISOString(),
        endpoints: {
            health: '/health',
            config: '/api/config',
            docs: '/api/docs',
            products: '/api/product-availability',
            flavors: '/api/flavor-availability',
            admin: '/api/admin/*',
            payment: '/api/create-payment', // ✅ Novo endpoint
            webhook: '/api/webhooks/mercadopago' // ✅ Webhook
        }
    });
});

// ========== DOCUMENTAÇÃO ==========
app.get('/api/docs', (req, res) => {
    res.json({
        api: 'BebCom Delivery API',
        version: API_VERSION,
        baseUrl: `${req.protocol}://${req.get('host')}`,
        endpoints: {
            public: [
                { method: 'GET', path: '/', description: 'Status da API' },
                { method: 'GET', path: '/health', description: 'Health check completo' },
                { method: 'GET', path: '/health/liveness', description: 'Azure liveness probe' },
                { method: 'GET', path: '/health/readiness', description: 'Azure readiness probe' },
                { method: 'GET', path: '/api/config', description: 'Configuração pública do frontend' },
                { method: 'GET', path: '/api/product-availability', description: 'Disponibilidade de produtos' },
                { method: 'GET', path: '/api/flavor-availability', description: 'Disponibilidade de sabores' },
                { method: 'GET', path: '/api/sync-all', description: 'Sincronizar todos os dados' },
                { method: 'POST', path: '/api/create-payment', description: 'Criar pagamento Mercado Pago' }
            ],
            webhooks: [
                { method: 'POST', path: '/api/webhooks/mercadopago', description: 'Webhook de notificação MP' }
            ],
            admin: [
                { method: 'POST', path: '/api/admin/verify', description: 'Verificar senha admin' },
                { method: 'POST', path: '/api/admin/product-availability/bulk', description: 'Atualizar produtos' },
                { method: 'POST', path: '/api/admin/flavor-availability/bulk', description: 'Atualizar sabores' }
            ]
        },
        timestamp: new Date().toISOString()
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
            address,
            notificationUrl,
            redirectUrls
        } = req.body;

        // Validações básicas
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

        // Se não tiver Mercado Pago configurado, retorna erro
        if (!mercadopagoClient) {
            return res.status(503).json({
                success: false,
                error: 'Mercado Pago não configurado no servidor'
            });
        }

        // Formata itens para o Mercado Pago
        const mpItems = items.map(item => ({
            id: item.id || `item-${Date.now()}`,
            title: item.title,
            description: item.description || item.title,
            quantity: Number(item.quantity),
            unit_price: Number(item.unit_price),
            currency_id: 'BRL'
        }));

        // Adiciona taxa de entrega como um item separado
        if (deliveryType === 'delivery' && deliveryFee > 0) {
            mpItems.push({
                id: 'delivery-fee',
                title: 'Taxa de Entrega',
                description: `Entrega em ${address?.street || 'endereço informado'}`,
                quantity: 1,
                unit_price: Number(deliveryFee),
                currency_id: 'BRL'
            });
        }

        // Prepara dados do comprador
        const payer = {
            name: customer.name,
            email: customer.email,
            phone: {
                number: customer.phone.replace(/\D/g, ''),
                area_code: customer.phone.replace(/\D/g, '').substring(0, 2)
            }
        };

        // Adiciona endereço se disponível
        if (address && address.street) {
            payer.address = {
                street_name: address.street,
                street_number: address.number || 's/n',
                complement: address.complement || ''
            };
        }

        // URLs de retorno (frontend)
        const successUrl = redirectUrls?.success || 
            `${req.headers.origin || 'https://bebcom.com.br'}/?status=approved&order_id=${orderId}`;
        const failureUrl = redirectUrls?.failure || 
            `${req.headers.origin || 'https://bebcom.com.br'}/?status=failure`;
        const pendingUrl = redirectUrls?.pending || 
            `${req.headers.origin || 'https://bebcom.com.br'}/?status=pending`;

        // Cria a preferência
        const preference = new Preference(mercadopagoClient);
        
        const preferenceData = {
            body: {
                items: mpItems,
                payer: payer,
                external_reference: orderId,
                back_urls: {
                    success: successUrl,
                    failure: failureUrl,
                    pending: pendingUrl
                },
                auto_return: 'approved',
                notification_url: notificationUrl || `${req.protocol}://${req.get('host')}/api/webhooks/mercadopago`,
                payment_methods: {
                    excluded_payment_methods: [],
                    excluded_payment_types: [],
                    installments: 12
                },
                statement_descriptor: 'BEBCOM DELIVERY',
                metadata: {
                    order_id: orderId,
                    delivery_type: deliveryType,
                    customer_name: customer.name,
                    customer_phone: customer.phone
                }
            }
        };

        // Se for PIX, configura para exibir apenas PIX
        if (paymentMethod === 'pix') {
            preferenceData.body.payment_methods = {
                excluded_payment_methods: [],
                excluded_payment_types: [{ id: 'credit_card' }, { id: 'debit_card' }, { id: 'ticket' }],
                installments: 1
            };
        }

        const result = await preference.create(preferenceData);

        // Salva no banco de dados (se conectado)
        if (app.locals.db) {
            await app.locals.db.collection('orders').insertOne({
                orderId: orderId,
                preferenceId: result.id,
                customer: customer,
                items: items,
                total: total,
                deliveryFee: deliveryFee,
                deliveryType: deliveryType,
                address: address,
                status: 'pending',
                createdAt: new Date(),
                updatedAt: new Date(),
                initPoint: result.init_point,
                sandboxInitPoint: result.sandbox_init_point
            });
        }

        // Retorna os links de pagamento
        res.json({
            success: true,
            preferenceId: result.id,
            initPoint: result.init_point,
            sandboxInitPoint: result.sandbox_init_point,
            orderId: orderId
        });

    } catch (error) {
        console.error('❌ Erro ao criar pagamento:', error);
        
        res.status(500).json({
            success: false,
            error: 'Erro ao criar pagamento',
            details: error.message
        });
    }
});

// ========== WEBHOOK DO MERCADO PAGO ==========
app.post('/api/webhooks/mercadopago', async (req, res) => {
    try {
        const { type, data } = req.body;
        
        console.log('📩 Webhook recebido:', { type, data });

        // Responde imediatamente para o Mercado Pago
        res.status(200).json({ received: true });

        // Processa em background
        setTimeout(async () => {
            try {
                if (type === 'payment' && data.id) {
                    // Busca informações do pagamento na API do Mercado Pago
                    // Nota: Isso requer uma chamada adicional à API com o access token
                    console.log(`💳 Pagamento ${data.id} recebido`);
                    
                    if (app.locals.db) {
                        // Atualiza status no banco
                        await app.locals.db.collection('orders').updateOne(
                            { 'metadata.payment_id': data.id },
                            { $set: { 
                                'payment_status': 'received',
                                'webhook_received_at': new Date()
                            } }
                        );
                    }
                }
            } catch (err) {
                console.error('❌ Erro no processamento do webhook:', err);
            }
        }, 100);

    } catch (error) {
        console.error('❌ Erro no webhook:', error);
        res.status(500).json({ error: 'Erro interno' });
    }
});

// ========== MIDDLEWARE DE AUTENTICAÇÃO ADMIN ==========
function authenticateAdmin(req, res, next) {
    const directPassword = req.body.password ||
        req.headers['x-admin-password'] ||
        req.headers['x-admin-key'] ||
        req.query.adminPassword;
    
    let token = null;
    const authHeader = req.headers['authorization'] || req.headers['Authorization'];
    if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7);
    }
    
    if (!directPassword && !token) {
        return res.status(401).json({
            success: false,
            error: 'Senha ou token não fornecido'
        });
    }

    const currentYear = new Date().getFullYear();
    
    if (directPassword) {
        const expectedHash = crypto
            .createHash('sha256')
            .update(ADMIN_PASSWORD)
            .digest('hex');

        const hashWithSalt = crypto
            .createHash('sha256')
            .update(ADMIN_PASSWORD + 'bebcom_' + currentYear)
            .digest('hex');

        if (directPassword === ADMIN_PASSWORD ||
            directPassword === expectedHash ||
            directPassword === hashWithSalt) {
            return next();
        }
    }
    
    if (token && token.length === 64 && /^[a-f0-9]+$/i.test(token)) {
        return next();
    }

    return res.status(401).json({
        success: false,
        error: 'Senha ou token inválido'
    });
}

// ========== INICIALIZAÇÃO DO MONGODB ==========
async function initializeMongoDB() {
    try {
        if (!MONGODB_URI) {
            console.error('❌ CRÍTICO: MONGODB_URI não configurada!');
            app.locals.isDBConnected = false;
            app.locals.db = null;
            return;
        }

        console.log('🔌 Conectando ao MongoDB Atlas...');

        const { MongoClient, ServerApiVersion } = require('mongodb');

        const client = new MongoClient(MONGODB_URI, {
            serverApi: {
                version: ServerApiVersion.v1,
                strict: true,
                deprecationErrors: true
            },
            serverSelectionTimeoutMS: 8000,
            connectTimeoutMS: 15000,
            socketTimeoutMS: 45000,
            maxPoolSize: 50,
            minPoolSize: 5,
            maxIdleTimeMS: 10000,
            retryWrites: true,
            retryReads: true
        });

        await client.connect();
        await client.db('admin').command({ ping: 1 });

        const db = client.db(DB_NAME);

        console.log('✅ MongoDB Atlas CONECTADO com sucesso!');
        console.log(`📊 Database: ${DB_NAME}`);

        app.locals.db = db;
        app.locals.mongoClient = client;
        app.locals.isDBConnected = true;

        await initializeCollections(db);
        setupMongoRoutes(app, db);

        setupGracefulShutdown();

    } catch (error) {
        console.error('❌ Falha na conexão MongoDB:', error.message);
        app.locals.isDBConnected = false;
        app.locals.db = null;

        setTimeout(() => {
            console.log('🔄 Tentando reconectar ao MongoDB...');
            initializeMongoDB();
        }, 30000);
    }
}

async function initializeCollections(db) {
    try {
        const collections = await db.listCollections().toArray();
        const existingNames = collections.map(c => c.name);

        const requiredCollections = [
            'products',
            'flavors',
            'orders',
            'admin_logs',
            'sync_queue',
            'customers',
            'payments' // ✅ Adicionado para pagamentos
        ];

        for (const name of requiredCollections) {
            if (!existingNames.includes(name)) {
                await db.createCollection(name);
                console.log(`📦 Collection criada: ${name}`);

                if (name === 'products' || name === 'flavors') {
                    await db.collection(name).createIndex({ type: 1 });
                    await db.collection(name).createIndex({ lastUpdated: -1 });
                }

                if (name === 'orders') {
                    await db.collection(name).createIndex({ orderId: 1 }, { unique: true });
                    await db.collection(name).createIndex({ timestamp: -1 });
                    await db.collection(name).createIndex({ customerPhone: 1 });
                    await db.collection(name).createIndex({ preferenceId: 1 });
                    await db.collection(name).createIndex({ status: 1 });
                }

                if (name === 'payments') {
                    await db.collection(name).createIndex({ paymentId: 1 }, { unique: true });
                    await db.collection(name).createIndex({ orderId: 1 });
                    await db.collection(name).createIndex({ status: 1 });
                    await db.collection(name).createIndex({ createdAt: -1 });
                }

                if (name === 'admin_logs') {
                    await db.collection(name).createIndex({ timestamp: -1 });
                    await db.collection(name).createIndex({ admin: 1 });
                }
            }
        }

        console.log('✅ Collections e índices configurados');
    } catch (error) {
        console.error('⚠️ Erro ao configurar collections:', error.message);
    }
}

// ========== ROTAS COM MONGODB ==========
function setupMongoRoutes(app, db) {

    app.get('/api/product-availability', async (req, res) => {
        try {
            const productData = await db.collection('products')
                .findOne({ type: 'availability' });

            res.json({
                success: true,
                productAvailability: productData?.data || {},
                lastUpdated: productData?.lastUpdated || new Date().toISOString(),
                offline: false,
                dbStatus: 'connected'
            });
        } catch (error) {
            console.error('❌ Erro ao buscar produtos:', error);
            res.status(500).json({
                success: false,
                error: 'Erro ao buscar produtos',
                productAvailability: {},
                offline: true,
                dbStatus: 'error'
            });
        }
    });

    app.get('/api/flavor-availability', async (req, res) => {
        try {
            const flavorData = await db.collection('flavors')
                .findOne({ type: 'availability' });

            res.json({
                success: true,
                flavorAvailability: flavorData?.data || {},
                lastUpdated: flavorData?.lastUpdated || new Date().toISOString(),
                offline: false,
                dbStatus: 'connected'
            });
        } catch (error) {
            console.error('❌ Erro ao buscar sabores:', error);
            res.status(500).json({
                success: false,
                error: 'Erro ao buscar sabores',
                flavorAvailability: {},
                offline: true,
                dbStatus: 'error'
            });
        }
    });

    app.get('/api/sync-all', async (req, res) => {
        try {
            const [products, flavors] = await Promise.all([
                db.collection('products').findOne({ type: 'availability' }),
                db.collection('flavors').findOne({ type: 'availability' })
            ]);

            res.json({
                success: true,
                productAvailability: products?.data || {},
                flavorAvailability: flavors?.data || {},
                lastSync: new Date().toISOString(),
                offline: false,
                dbStatus: 'connected'
            });
        } catch (error) {
            console.error('❌ Erro na sincronização:', error);
            res.status(500).json({
                success: false,
                error: 'Erro na sincronização',
                dbStatus: 'error'
            });
        }
    });

    app.post('/api/admin/product-availability/bulk', adminLimiter, authenticateAdmin, async (req, res) => {
        try {
            if (!db) {
                return res.status(503).json({
                    success: false,
                    error: 'Banco de dados indisponível'
                });
            }

            const { productAvailability, adminName, source } = req.body;

            if (!productAvailability || typeof productAvailability !== 'object') {
                return res.status(400).json({
                    success: false,
                    error: 'Dados inválidos'
                });
            }

            const result = await db.collection('products').updateOne(
                { type: 'availability' },
                {
                    $set: {
                        data: productAvailability,
                        lastUpdated: new Date().toISOString(),
                        updatedAt: new Date(),
                        updatedBy: adminName || 'Admin BebCom',
                        source: source || 'direct',
                        version: API_VERSION
                    }
                },
                { upsert: true }
            );

            await db.collection('admin_logs').insertOne({
                action: 'update_products',
                admin: adminName || 'Admin BebCom',
                count: Object.keys(productAvailability).length,
                source: source || 'direct',
                timestamp: new Date(),
                version: API_VERSION
            });

            res.json({
                success: true,
                message: 'Produtos atualizados com sucesso',
                timestamp: new Date().toISOString(),
                count: Object.keys(productAvailability).length,
                upserted: result.upsertedId ? true : false
            });

        } catch (error) {
            console.error('❌ Erro ao salvar produtos:', error);
            res.status(500).json({
                success: false,
                error: `Erro ao salvar produtos: ${error.message}`
            });
        }
    });

    app.post('/api/admin/flavor-availability/bulk', adminLimiter, authenticateAdmin, async (req, res) => {
        try {
            if (!db) {
                return res.status(503).json({
                    success: false,
                    error: 'Banco de dados indisponível'
                });
            }

            const { flavorAvailability, adminName, source } = req.body;

            if (!flavorAvailability || typeof flavorAvailability !== 'object') {
                return res.status(400).json({
                    success: false,
                    error: 'Dados inválidos'
                });
            }

            const result = await db.collection('flavors').updateOne(
                { type: 'availability' },
                {
                    $set: {
                        data: flavorAvailability,
                        lastUpdated: new Date().toISOString(),
                        updatedAt: new Date(),
                        updatedBy: adminName || 'Admin BebCom',
                        source: source || 'direct',
                        version: API_VERSION
                    }
                },
                { upsert: true }
            );

            await db.collection('admin_logs').insertOne({
                action: 'update_flavors',
                admin: adminName || 'Admin BebCom',
                count: Object.keys(flavorAvailability).length,
                source: source || 'direct',
                timestamp: new Date(),
                version: API_VERSION
            });

            res.json({
                success: true,
                message: 'Sabores atualizados com sucesso',
                timestamp: new Date().toISOString(),
                count: Object.keys(flavorAvailability).length,
                upserted: result.upsertedId ? true : false
            });

        } catch (error) {
            console.error('❌ Erro ao salvar sabores:', error);
            res.status(500).json({
                success: false,
                error: `Erro ao salvar sabores: ${error.message}`
            });
        }
    });

    console.log('✅ Rotas MongoDB configuradas');
}

// ========== GRACEFUL SHUTDOWN ==========
function setupGracefulShutdown() {
    const gracefulShutdown = async (signal) => {
        console.log(`\n👋 Recebido ${signal}, encerrando graciosamente...`);

        server.close(() => {
            console.log('✅ Servidor HTTP encerrado');
        });

        if (app.locals.mongoClient) {
            try {
                await app.locals.mongoClient.close();
                console.log('✅ Conexão MongoDB encerrada');
            } catch (err) {
                console.error('❌ Erro ao encerrar MongoDB:', err);
            }
        }

        setTimeout(() => {
            console.log('👋 Encerrando processo');
            process.exit(0);
        }, 3000);
    };

    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
    process.on('SIGHUP', () => gracefulShutdown('SIGHUP'));
}

// ========== ERROR HANDLERS ==========
process.on('uncaughtException', (error) => {
    console.error('💥 ERRO NÃO CAPTURADO:', error);
    console.error('Stack:', error.stack);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('💥 PROMESSA REJEITADA NÃO TRATADA:', reason);
    console.error('Promise:', promise);
});

// ========== INICIAR SERVIDOR ==========
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log('='.repeat(70));
    console.log('🚀 SERVIDOR BEBCOM INICIADO NO AZURE');
    console.log('='.repeat(70));
    console.log(`📡 Endereço: http://0.0.0.0:${PORT}`);
    console.log(`🩺 Health: http://0.0.0.0:${PORT}/health`);
    console.log(`⚙️  Config: http://0.0.0.0:${PORT}/api/config`);
    console.log(`💳 Pagamento: http://0.0.0.0:${PORT}/api/create-payment`);
    console.log(`📚 Docs: http://0.0.0.0:${PORT}/api/docs`);
    console.log(`🔐 Admin Verify: http://0.0.0.0:${PORT}/api/admin/verify`);
    console.log(`🌍 Ambiente: ${NODE_ENV}`);
    console.log(`🕒 Início: ${new Date().toISOString()}`);
    console.log(`🔒 Rate Limit Admin: 5 tentativas / 15 minutos`);
    console.log('='.repeat(70));

    setTimeout(initializeMongoDB, 1000);
});

server.timeout = 120000;
server.keepAliveTimeout = 65000;
server.headersTimeout = 66000;

module.exports = app;
