// backend/server.js - VERSÃO PRODUÇÃO PARA AZURE
const express = require('express');
const cors = require('cors');
const http = require('http');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit'); // NOVO

const app = express();
const PORT = process.env.PORT || 8080; // Azure usa porta dinâmica

// ========== NOVO: VALIDAÇÃO DE VARIÁVEIS CRÍTICAS ==========
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
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD; // REMOVIDO FALLBACK
const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = process.env.DB_NAME || 'bebcom_delivery';
const API_VERSION = '3.4.0-azure';

// ========== NOVO: RATE LIMITING ==========
const adminLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 5, // 5 tentativas
    skipSuccessfulRequests: true,
    message: {
        success: false,
        error: 'Muitas tentativas de admin. Aguarde 15 minutos.'
    },
    standardHeaders: true,
    legacyHeaders: false
});

// Middleware - CORS (mantido original)
app.use(cors({
    origin: process.env.CORS_ORIGIN || '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-admin-password', 'x-admin-key']
}));

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
console.log(`🆔 PID: ${process.pid}`);
console.log('='.repeat(70));

// ========== HEALTH CHECKS OTIMIZADOS ==========
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
        dbStatus: app.locals.isDBConnected ? 'connected' : 'disconnected'
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
            docs: '/api/docs',
            products: '/api/product-availability',
            flavors: '/api/flavor-availability',
            admin: '/api/admin/*'
        }
    });
});

// ========== DOCUMENTAÇÃO SIMPLES ==========
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
                { method: 'GET', path: '/api/product-availability', description: 'Disponibilidade de produtos' },
                { method: 'GET', path: '/api/flavor-availability', description: 'Disponibilidade de sabores' },
                { method: 'GET', path: '/api/sync-all', description: 'Sincronizar todos os dados' }
                // REMOVIDO: /api/admin-password da documentação pública
            ],
            admin: [
                { method: 'POST', path: '/api/admin/product-availability/bulk', description: 'Atualizar produtos' },
                { method: 'POST', path: '/api/admin/flavor-availability/bulk', description: 'Atualizar sabores' }
            ]
        },
        timestamp: new Date().toISOString()
    });
});

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

        // Configurar graceful shutdown
        setupGracefulShutdown();

    } catch (error) {
        console.error('❌ Falha na conexão MongoDB:', error.message);
        app.locals.isDBConnected = false;
        app.locals.db = null;

        // Tentar reconectar após 30 segundos
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
            'customers'
        ];

        for (const name of requiredCollections) {
            if (!existingNames.includes(name)) {
                await db.createCollection(name);
                console.log(`📦 Collection criada: ${name}`);

                // Criar índices
                if (name === 'products' || name === 'flavors') {
                    await db.collection(name).createIndex({ type: 1 });
                    await db.collection(name).createIndex({ lastUpdated: -1 });
                }

                if (name === 'orders') {
                    await db.collection(name).createIndex({ orderId: 1 }, { unique: true });
                    await db.collection(name).createIndex({ timestamp: -1 });
                    await db.collection(name).createIndex({ customerPhone: 1 });
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

// ========== MIDDLEWARE DE AUTENTICAÇÃO ==========
function authenticateAdmin(req, res, next) {
    const password = req.body.password ||
        req.headers['x-admin-password'] ||
        req.headers['x-admin-key'] ||
        req.query.adminPassword;

    if (!password) {
        return res.status(401).json({
            success: false,
            error: 'Senha administrativa não fornecida'
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
        next();
    } else {
        return res.status(401).json({
            success: false,
            error: 'Senha administrativa incorreta'
        });
    }
}

// ========== ROTAS PÚBLICAS ==========
// REMOVIDA: Rota /api/admin-password (não deve existir em produção)

// ========== ROTAS COM MONGODB ==========
function setupMongoRoutes(app, db) {

    // GET - Disponibilidade de produtos
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

    // GET - Disponibilidade de sabores
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

    // GET - Sincronização completa
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

    // POST - Atualizar produtos (admin) - ADICIONADO RATE LIMIT
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

            // Registrar log
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

    // POST - Atualizar sabores (admin) - ADICIONADO RATE LIMIT
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
    console.log(`📚 Docs: http://0.0.0.0:${PORT}/api/docs`);
    console.log(`🌍 Ambiente: ${NODE_ENV}`);
    console.log(`🕒 Início: ${new Date().toISOString()}`);
    console.log(`🔒 Rate Limit Admin: 5 tentativas / 15 minutos`); // NOVO LOG
    console.log('='.repeat(70));

    // Inicializar MongoDB após 1 segundo
    setTimeout(initializeMongoDB, 1000);
});

// Timeout do servidor
server.timeout = 120000; // 2 minutos
server.keepAliveTimeout = 65000;
server.headersTimeout = 66000;

// ========== EXPORTAR PARA TESTES ==========
module.exports = app;