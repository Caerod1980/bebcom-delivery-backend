// backend/server.js - VERSÃO ESTÁVEL PARA PRODUÇÃO
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { MongoClient, ObjectId } = require('mongodb');
const mercadopago = require('mercadopago');
const { 
    processUberDelivery,
    createUberDeliveryQuote
} = require('./services/uberDirectService');

const app = express();
app.set('trust proxy', 1); // Confia no primeiro proxy (Azure)
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

// ========== RATE LIMITING - CORRIGIDO ==========
const extractIp = (req) => {
    // Pega o IP do proxy (Azure) ou do req.ip
    const ip = req.headers['x-forwarded-for']?.split(',').shift() || 
               req.ip || 
               req.connection.remoteAddress;
    
    // Remove a porta se existir (ex: "179.225.249.130:49309" -> "179.225.249.130")
    if (ip && ip.includes(':')) {
        return ip.split(':')[0];
    }
    
    return ip || '0.0.0.0';
};

const adminLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    skipSuccessfulRequests: true,
    keyGenerator: extractIp,
    message: {
        success: false,
        error: 'Muitas tentativas de admin. Aguarde 15 minutos.'
    }
});

const paymentLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 10,
    keyGenerator: extractIp,
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
        'Accept'
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
        backendUrl: backendUrl,
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
            payment: '/api/create-payment',
            adminOrders: '/api/admin/orders',
            adminStats: '/api/admin/orders/stats'
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

// ========== COTAÇÃO UBER DIRECT ==========
app.post('/api/uber/quote', paymentLimiter, async (req, res) => {
    try {
        const { address, items, subtotal } = req.body;

        if (!address) {
            return res.status(400).json({
                success: false,
                error: 'Endereço obrigatório para cotação'
            });
        }

        if (!items || !Array.isArray(items) || items.length === 0) {
            return res.status(400).json({
                success: false,
                error: 'Itens obrigatórios para cotação'
            });
        }

        const quote = await createUberDeliveryQuote(address);

        console.log('🚚 Cotação Uber Direct criada:', {
            quoteId: quote.quoteId,
            fee: quote.fee,
            currency: quote.currency,
            expiresAt: quote.expiresAt
        });

        res.json({
            success: true,
            uberFee: quote.fee,
            deliveryFee: quote.fee,
            quoteId: quote.quoteId,
            expiresAt: quote.expiresAt,
            currency: quote.currency,
            raw: quote.raw
        });

    } catch (error) {
        console.error('❌ Erro na cotação Uber:', error);

        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// ========== ENDPOINT DE PAGAMENTO MERCADO PAGO CORRIGIDO ==========
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
    uberQuote
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

        // ✅ CORREÇÃO: Limpa o telefone (remove tudo que não é número)
        const cleanPhone = customer.phone.replace(/\D/g, '');
        
        // ✅ Valida se o telefone tem pelo menos 10 dígitos
        if (cleanPhone.length < 10 || cleanPhone.length > 11) {
            return res.status(400).json({
                success: false,
                error: 'Telefone inválido. Use DDD + número (10 ou 11 dígitos)'
            });
        }

        // ✅ CORREÇÃO: Limpa o CPF se existir
        const cleanCpf = customer.cpf ? customer.cpf.replace(/\D/g, '') : '';

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

        // URLs de retorno - CORRIGIDO com https
        const baseUrl = 'https://caerod1980.github.io/bebcom-delivery-backend';
        const successUrl = `${baseUrl}?status=approved&order_id=${orderId}`;
        const failureUrl = `${baseUrl}?status=failure`;
        const pendingUrl = `${baseUrl}?status=pending`;

        // Cria preferência - AGORA COM CPF (se disponível)
        const preference = {
            items: mpItems,
            payer: {
                name: customer.name,
                email: customer.email,
                phone: {
                    number: Number(cleanPhone)
                },
                ...(cleanCpf && {
                    identification: {
                        type: 'CPF',
                        number: cleanCpf
                    }
                })
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
                uberQuote: uberQuote || null,
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
            error: 'Erro ao criar pagamento',
            details: error.message
        });
    }
});

// ========== WEBHOOK DO MERCADO PAGO - CORRIGIDO ==========
app.post('/api/webhooks/mercadopago', async (req, res) => {
    try {
        const { type, data } = req.body;
        console.log('📩 Webhook recebido:', JSON.stringify({ type, data }, null, 2));

        // Responde imediatamente para o Mercado Pago (200 OK)
        res.status(200).json({ received: true });

        // Se não tem data ou type, ignora
        if (!data || !data.id) {
            console.log('⚠️ Webhook sem dados, ignorando');
            return;
        }

        // Processa em background (não bloqueia a resposta)
        setTimeout(async () => {
            try {
                if (!app.locals.db) {
                    console.log('⚠️ Banco de dados indisponível');
                    return;
                }

                // Busca o pedido pelo payment_id (se for webhook de pagamento)
                if (type === 'payment') {
                    console.log(`💳 Processando pagamento ID: ${data.id}`);
                    
                    // Primeiro tenta encontrar pelo payment_id
                   const paymentResponse = await mercadopago.payment.findById(data.id);
const payment = paymentResponse.body;

console.log('💳 Pagamento Mercado Pago consultado:', {
    id: payment.id,
    status: payment.status,
    status_detail: payment.status_detail,
    external_reference: payment.external_reference,
    payment_method_id: payment.payment_method_id,
    payment_type_id: payment.payment_type_id,
    issuer_id: payment.issuer_id,
    installments: payment.installments,
    transaction_amount: payment.transaction_amount,
    card: payment.card ? {
        first_six_digits: payment.card.first_six_digits,
        last_four_digits: payment.card.last_four_digits,
        cardholder: payment.card.cardholder
    } : null
});

let order = await app.locals.db.collection('orders').findOne({
    orderId: payment.external_reference
});

if (!order) {
    order = await app.locals.db.collection('orders').findOne({
        payment_id: String(payment.id)
    });
}
                    
                    if (order) {
                        console.log(`📦 Pedido encontrado: ${order.orderId}`);
                        
                        await app.locals.db.collection('orders').updateOne(
    { _id: order._id },
    { 
        $set: { 
            status: payment.status === 'approved' ? 'approved' : payment.status,
            payment_id: String(payment.id),
            paymentStatus: payment.status,
            paymentStatusDetail: payment.status_detail,
            paymentMethodId: payment.payment_method_id,
            updatedAt: new Date(),
            webhookReceived: true
        } 
    }
);

console.log(`✅ Pedido ${order.orderId} atualizado para status: ${payment.status}`);

if (payment.status !== 'approved') {
    console.log(`⏳ Pagamento ${payment.id} ainda não aprovado: ${payment.status}`);
    return;
}

// 🚚 AUTOMAÇÃO UBER DIRECT
if (
    order.deliveryType === 'delivery' &&
    !order.uberDelivery?.deliveryId &&
    order.uberDelivery?.status !== 'processing'
) {

    // 🔒 trava anti duplicidade
    await app.locals.db.collection('orders').updateOne(
        { _id: order._id },
        {
            $set: {
                'uberDelivery.status': 'processing',
                'uberDelivery.processingStartedAt': new Date()
            }
        }
    );

    const updatedOrder = await app.locals.db.collection('orders').findOne({
        _id: order._id
    });

    const uberResult = await processUberDelivery(updatedOrder, app.locals.db);

    console.log('🚚 Resultado Uber Direct:', {
        orderId: order.orderId,
        success: uberResult.success,
        deliveryId: uberResult.deliveryId,
        simulated: uberResult.simulated,
        error: uberResult.error
    });

} else {
    console.log(`ℹ️ Uber Direct ignorado para pedido ${order.orderId}`, {
        deliveryType: order.deliveryType,
        uberDelivery: order.uberDelivery
    });
}
                    } else {
                        console.log(`❌ Pedido não encontrado para payment_id: ${data.id}`);
                        
                        // Cria collection webhooks se não existir (para salvar notificações não processadas)
                        try {
                            await app.locals.db.collection('webhooks').insertOne({
                                type,
                                paymentId: data.id,
                                receivedAt: new Date(),
                                processed: false
                            });
                        } catch (e) {
                            // Collection pode não existir, ignora
                        }
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

// ========== NOVO ENDPOINT: GET /api/admin/orders (LISTAR PEDIDOS) ==========
app.get('/api/admin/orders', async (req, res) => {
    try {
        if (!app.locals.db) {
            return res.status(503).json({ 
                success: false, 
                error: 'Banco de dados indisponível' 
            });
        }

        const orders = app.locals.db.collection('orders');
        
        // Parâmetros de consulta (filtros)
        const { 
            type,           // 'delivery' ou 'pickup'
            status,         // 'paid', 'pending', 'all'
            startDate,      // formato: YYYY-MM-DD
            endDate,        // formato: YYYY-MM-DD
            search,         // nome, whatsapp ou orderId
            page = 1,
            limit = 50
        } = req.query;
        
        // Construir filtro MongoDB
        const filter = {};
        
        if (type && type !== 'all') filter.deliveryType = type;
        
        if (status === 'paid') filter.status = 'approved';
        else if (status === 'pending') filter.status = 'pending';
        
        if (startDate || endDate) {
            filter.createdAt = {};
            if (startDate) filter.createdAt.$gte = new Date(startDate);
            if (endDate) {
                const end = new Date(endDate);
                end.setHours(23, 59, 59, 999);
                filter.createdAt.$lte = end;
            }
        }
        
        if (search) {
            filter.$or = [
                { 'customer.name': { $regex: search, $options: 'i' } },
                { 'customer.phone': { $regex: search, $options: 'i' } },
                { 'customer.email': { $regex: search, $options: 'i' } },
                { 'orderId': { $regex: search, $options: 'i' } }
            ];
        }
        
        // Paginação
        const skip = (parseInt(page) - 1) * parseInt(limit);
        
        // Buscar pedidos (ordenados do mais recente)
        const allOrders = await orders
            .find(filter)
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(parseInt(limit))
            .toArray();
        
        // Total de pedidos (para paginação)
        const total = await orders.countDocuments(filter);
        
        // Estatísticas rápidas
        const stats = {
            total: allOrders.length,
            totalRevenue: allOrders.reduce((sum, o) => sum + (o.total || 0), 0),
            deliveries: allOrders.filter(o => o.deliveryType === 'delivery').length,
            pickups: allOrders.filter(o => o.deliveryType === 'pickup').length,
            paid: allOrders.filter(o => o.status === 'approved').length,
            pending: allOrders.filter(o => o.status === 'pending').length
        };
        
        res.json({
            success: true,
            page: parseInt(page),
            totalPages: Math.ceil(total / parseInt(limit)),
            totalOrders: total,
            stats,
            orders: allOrders
        });
        
    } catch (error) {
        console.error('❌ Erro ao buscar pedidos:', error);
        res.status(500).json({ 
            success: false, 
            error: error.message 
        });
    }
});

// ========== NOVO ENDPOINT: GET /api/admin/orders/stats (ESTATÍSTICAS) ==========
app.get('/api/admin/orders/stats', async (req, res) => {
    try {
        if (!app.locals.db) {
            return res.status(503).json({ 
                success: false, 
                error: 'Banco de dados indisponível' 
            });
        }

        const orders = app.locals.db.collection('orders');
        
        // Data de hoje (início do dia)
        const hoje = new Date();
        hoje.setHours(0, 0, 0, 0);
        
        const amanha = new Date(hoje);
        amanha.setDate(amanha.getDate() + 1);
        
        // Pipeline de agregação para estatísticas
        const stats = await orders.aggregate([
            {
                $facet: {
                    geral: [
                        {
                            $group: {
                                _id: null,
                                totalPedidos: { $sum: 1 },
                                faturamentoTotal: { $sum: "$total" },
                                ticketMedio: { $avg: "$total" }
                            }
                        }
                    ],
                    hoje: [
                        {
                            $match: {
                                createdAt: { $gte: hoje, $lt: amanha }
                            }
                        },
                        {
                            $group: {
                                _id: null,
                                quantidade: { $sum: 1 },
                                faturamento: { $sum: "$total" }
                            }
                        }
                    ],
                    porTipo: [
                        {
                            $group: {
                                _id: "$deliveryType",
                                count: { $sum: 1 }
                            }
                        }
                    ],
                    porStatus: [
                        {
                            $group: {
                                _id: "$status",
                                count: { $sum: 1 }
                            }
                        }
                    ]
                }
            }
        ]).toArray();
        
        const result = stats[0] || {};
        
        res.json({
            success: true,
            stats: {
                total: result.geral[0]?.totalPedidos || 0,
                faturamentoTotal: result.geral[0]?.faturamentoTotal || 0,
                ticketMedio: result.geral[0]?.ticketMedio || 0,
                
                hoje: result.hoje[0]?.quantidade || 0,
                faturamentoHoje: result.hoje[0]?.faturamento || 0,
                
                entregas: result.porTipo?.find(t => t._id === 'delivery')?.count || 0,
                retiradas: result.porTipo?.find(t => t._id === 'pickup')?.count || 0,
                
                pagos: result.porStatus?.find(s => s._id === 'approved')?.count || 0,
                pendentes: result.porStatus?.find(s => s._id === 'pending')?.count || 0
            }
        });
        
    } catch (error) {
        console.error('❌ Erro nas estatísticas:', error);
        res.status(500).json({ 
            success: false, 
            error: error.message 
        });
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

// ========== ROTA PARA VERIFICAR STATUS DO PAGAMENTO ==========
app.get('/api/payment-status/:orderId', async (req, res) => {
    try {
        const { orderId } = req.params;
        const { paymentId } = req.query;
        
        console.log(`🔍 Verificando status do pedido: ${orderId}`);
        
        if (!app.locals.db) {
            return res.json({ 
                success: false, 
                error: 'Banco de dados indisponível',
                status: 'pending' 
            });
        }

        // Busca o pedido no banco
        let order = await app.locals.db.collection('orders').findOne({ orderId: orderId });
        
        if (!order && paymentId) {
            order = await app.locals.db.collection('orders').findOne({ 
                payment_id: paymentId 
            });
        }
        
        if (!order) {
            return res.json({ 
                success: false, 
                error: 'Pedido não encontrado',
                status: 'pending' 
            });
        }

        // Se o status ainda é pending mas já passou muito tempo, marca como expired
        const timeSinceCreation = Date.now() - new Date(order.createdAt).getTime();
        if (order.status === 'pending' && timeSinceCreation > 30 * 60 * 1000) {
            await app.locals.db.collection('orders').updateOne(
                { _id: order._id },
                { $set: { status: 'expired', updatedAt: new Date() } }
            );
            order.status = 'expired';
        }

        res.json({
            success: true,
            status: order.status || 'pending',
            orderId: order.orderId,
            paymentId: order.payment_id,
            createdAt: order.createdAt,
            updatedAt: order.updatedAt
        });

    } catch (error) {
        console.error('❌ Erro ao verificar status:', error);
        res.status(500).json({ 
            success: false, 
            error: error.message,
            status: 'pending' 
        });
    }
});

// =====================================================
// 🎮 CLUBE BEBCOM — PASSAPORTE GAMER
// =====================================================

function normalizePhone(phone = '') {
    return String(phone).replace(/\D/g, '');
}

function calculateLevel(xp = 0) {
    if (xp >= 1000) return 10;
    if (xp >= 800) return 8;
    if (xp >= 600) return 6;
    if (xp >= 400) return 4;
    if (xp >= 200) return 3;
    if (xp >= 100) return 2;
    return 1;
}

// LOGIN / CADASTRO SIMPLES
app.post('/api/clube/login', async (req, res) => {
    try {
        if (!app.locals.db) {
            return res.status(503).json({
                success: false,
                error: 'Banco de dados indisponível'
            });
        }

        const { name, phone } = req.body;
        const normalizedPhone = normalizePhone(phone);

        if (!normalizedPhone || normalizedPhone.length < 10) {
            return res.status(400).json({
                success: false,
                error: 'Telefone inválido'
            });
        }

        const users = app.locals.db.collection('clube_users');

        let user = await users.findOne({ phone: normalizedPhone });

        if (!user) {
            user = {
                name: name || 'Jogador Bebcom',
                phone: normalizedPhone,
                xp: 0,
                level: 1,
                avatar: {
                    name: 'Explorador Bebcom',
                    skin: 'default',
                    items: []
                },
                stats: {
                    scans: 0,
                    missionsCompleted: 0,
                    rewardsUnlocked: 0
                },
                createdAt: new Date(),
                updatedAt: new Date()
            };

            await users.insertOne(user);
        } else if (name && name !== user.name) {
            await users.updateOne(
                { phone: normalizedPhone },
                {
                    $set: {
                        name,
                        updatedAt: new Date()
                    }
                }
            );

            user.name = name;
        }

        res.json({
            success: true,
            user
        });

    } catch (error) {
        console.error('❌ Erro no login Clube:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// PERFIL DO JOGADOR
app.get('/api/clube/perfil/:phone', async (req, res) => {
    try {
        if (!app.locals.db) {
            return res.status(503).json({
                success: false,
                error: 'Banco de dados indisponível'
            });
        }

        const phone = normalizePhone(req.params.phone);

        const user = await app.locals.db.collection('clube_users').findOne({ phone });

        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'Jogador não encontrado'
            });
        }

        const scans = await app.locals.db.collection('clube_scans')
            .find({ phone })
            .sort({ createdAt: -1 })
            .limit(20)
            .toArray();

        const rewards = await app.locals.db.collection('clube_coupons')
            .find({ phone })
            .sort({ createdAt: -1 })
            .toArray();

        res.json({
            success: true,
            user,
            scans,
            rewards
        });

    } catch (error) {
        console.error('❌ Erro ao buscar perfil Clube:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// MISSÕES ATIVAS
app.get('/api/clube/missoes', async (req, res) => {
    try {
        if (!app.locals.db) {
            return res.status(503).json({
                success: false,
                error: 'Banco de dados indisponível'
            });
        }

        const missions = await app.locals.db.collection('clube_missions')
            .find({ active: true })
            .sort({ createdAt: -1 })
            .toArray();

        res.json({
            success: true,
            missions
        });

    } catch (error) {
        console.error('❌ Erro ao buscar missões:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// ESCANEAR / VALIDAR QR CODE
app.post('/api/clube/escanear', async (req, res) => {
    try {
        if (!app.locals.db) {
            return res.status(503).json({
                success: false,
                error: 'Banco de dados indisponível'
            });
        }

        const { phone, code } = req.body;

        const normalizedPhone = normalizePhone(phone);
        const normalizedCode = String(code || '').trim().toUpperCase();

        if (!normalizedPhone || normalizedPhone.length < 10) {
            return res.status(400).json({
                success: false,
                error: 'Telefone inválido'
            });
        }

        if (!normalizedCode) {
            return res.status(400).json({
                success: false,
                error: 'Código QR inválido'
            });
        }

        const users = app.locals.db.collection('clube_users');
        const qrcodes = app.locals.db.collection('clube_qrcodes');
        const scans = app.locals.db.collection('clube_scans');
        const coupons = app.locals.db.collection('clube_coupons');

        const user = await users.findOne({ phone: normalizedPhone });

        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'Faça login no Clube antes de escanear'
            });
        }

        const qr = await qrcodes.findOne({ code: normalizedCode });

        if (!qr) {
            return res.status(404).json({
                success: false,
                error: 'Código não encontrado'
            });
        }

        if (qr.used) {
            return res.status(409).json({
                success: false,
                error: 'Este QR Code já foi utilizado'
            });
        }

        if (qr.expiresAt && new Date(qr.expiresAt) < new Date()) {
            return res.status(410).json({
                success: false,
                error: 'Este QR Code expirou'
            });
        }

        const xpGained = Number(qr.xp || 10);
        const newXp = Number(user.xp || 0) + xpGained;
        const newLevel = calculateLevel(newXp);

        await qrcodes.updateOne(
            { code: normalizedCode },
            {
                $set: {
                    used: true,
                    usedBy: normalizedPhone,
                    usedAt: new Date()
                }
            }
        );

        await scans.insertOne({
            phone: normalizedPhone,
            code: normalizedCode,
            product: qr.product || 'Produto participante',
            category: qr.category || 'geral',
            missionId: qr.missionId || null,
            xp: xpGained,
            createdAt: new Date()
        });

        await users.updateOne(
            { phone: normalizedPhone },
            {
                $set: {
                    xp: newXp,
                    level: newLevel,
                    updatedAt: new Date()
                },
                $inc: {
                    'stats.scans': 1
                }
            }
        );

        let reward = null;

        if (newXp >= 100 && !user.firstRewardUnlocked) {
            const couponCode = `CLUBE${crypto.randomBytes(3).toString('hex').toUpperCase()}`;

            reward = {
                phone: normalizedPhone,
                code: couponCode,
                title: 'Primeira recompensa desbloqueada',
                description: 'Cupom especial do Clube Bebcom',
                type: 'discount',
                value: 5,
                status: 'available',
                deliveryUrl: `https://caerod1980.github.io/bebcom-delivery-backend/?cupom=${couponCode}`,
                createdAt: new Date()
            };

            await coupons.insertOne(reward);

            await users.updateOne(
                { phone: normalizedPhone },
                {
                    $set: {
                        firstRewardUnlocked: true
                    },
                    $inc: {
                        'stats.rewardsUnlocked': 1
                    }
                }
            );
        }

        res.json({
            success: true,
            message: `Você ganhou ${xpGained} XP!`,
            xpGained,
            newXp,
            newLevel,
            product: qr.product || 'Produto participante',
            reward
        });

    } catch (error) {
        console.error('❌ Erro ao escanear QR:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// ADMIN — GERAR QR CODES EM LOTE
app.post('/api/admin/clube/qrcodes/gerar', adminLimiter, authenticateAdmin, async (req, res) => {
    try {
        if (!app.locals.db) {
            return res.status(503).json({
                success: false,
                error: 'Banco de dados indisponível'
            });
        }

        const {
            product = 'Produto participante',
            category = 'geral',
            quantity = 10,
            xp = 10,
            missionId = null
        } = req.body;

        const total = Math.min(Number(quantity) || 10, 500);

        const docs = [];

        for (let i = 0; i < total; i++) {
            docs.push({
                code: `BEBCOM-${crypto.randomBytes(5).toString('hex').toUpperCase()}`,
                product,
                category,
                xp: Number(xp) || 10,
                missionId,
                used: false,
                createdAt: new Date()
            });
        }

        await app.locals.db.collection('clube_qrcodes').insertMany(docs);

        res.json({
            success: true,
            total,
            qrcodes: docs
        });

    } catch (error) {
        console.error('❌ Erro ao gerar QR Codes:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// ADMIN — CRIAR MISSÃO SIMPLES
app.post('/api/admin/clube/missoes/criar', adminLimiter, authenticateAdmin, async (req, res) => {
    try {
        if (!app.locals.db) {
            return res.status(503).json({
                success: false,
                error: 'Banco de dados indisponível'
            });
        }

        const {
            title,
            description,
            targetXp = 100,
            rewardTitle = 'Recompensa Bebcom'
        } = req.body;

        if (!title) {
            return res.status(400).json({
                success: false,
                error: 'Título da missão é obrigatório'
            });
        }

        const mission = {
            title,
            description: description || '',
            targetXp: Number(targetXp) || 100,
            rewardTitle,
            active: true,
            createdAt: new Date()
        };

        const result = await app.locals.db.collection('clube_missions').insertOne(mission);

        res.json({
            success: true,
            missionId: result.insertedId,
            mission
        });

    } catch (error) {
        console.error('❌ Erro ao criar missão:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
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
       const collections = [
    'products',
    'flavors',
    'orders',
    'admin_logs',
    'uber_webhooks',
    'webhooks',

    // Clube Bebcom
    'clube_users',
    'clube_qrcodes',
    'clube_scans',
    'clube_missions',
    'clube_rewards',
    'clube_coupons'
];
        for (const name of collections) {
            try {
                await db.createCollection(name);
                console.log(`📦 Collection criada: ${name}`);
            } catch (e) {
                // Collection já existe
            }
        }

        // Tenta criar collection webhooks (se não existir)
        try {
            await db.createCollection('webhooks');
            console.log('📦 Collection webhooks criada');
        } catch (e) {
            // Já existe, ignora
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

// ========== WEBHOOK UBER DIRECT ==========
app.post('/api/webhooks/uber-direct', async (req, res) => {
    try {
        console.log('🚚 Webhook Uber Direct recebido:', JSON.stringify(req.body, null, 2));

        // Responde rápido para a Uber
        res.status(200).json({ received: true });

        if (!app.locals.db) {
            console.log('⚠️ Banco indisponível para webhook Uber');
            return;
        }

        const body = req.body || {};

        const eventId = body.event_id || body.eventId || null;
        const eventType = body.event_type || body.eventType || body.kind || '';
        const status = body.status || body.data?.status || body.meta?.status || null;
        const data = body.data || body.meta || body.resource || {};

        const deliveryId =
            data.id ||
            data.delivery_id ||
            data.deliveryId ||
            body.delivery_id ||
            body.deliveryId ||
            data.external_delivery_id ||
            null;

        const externalDeliveryId =
            data.external_delivery_id ||
            data.externalDeliveryId ||
            body.external_delivery_id ||
            body.externalDeliveryId ||
            null;

        // Evita processar o mesmo evento duas vezes
        if (eventId) {
            const alreadyProcessed = await app.locals.db.collection('uber_webhooks').findOne({
                eventId
            });

            if (alreadyProcessed) {
                console.log(`ℹ️ Webhook Uber duplicado ignorado: ${eventId}`);
                return;
            }

            await app.locals.db.collection('uber_webhooks').insertOne({
                eventId,
                eventType,
                status,
                deliveryId,
                externalDeliveryId,
                raw: body,
                receivedAt: new Date()
            });
        }

        const filter = {
            $or: [
                { 'uberDelivery.deliveryId': deliveryId },
                { orderId: externalDeliveryId },
                { 'uberDelivery.raw.id': deliveryId },
                { 'uberDelivery.raw.external_delivery_id': externalDeliveryId }
            ].filter(condition => {
                const value = Object.values(condition)[0];
                return value !== null && value !== undefined && value !== '';
            })
        };

        if (!filter.$or.length) {
            console.log('⚠️ Webhook Uber sem deliveryId/orderId reconhecível');
            return;
        }

        const normalizedStatus = normalizeUberDeliveryStatus(status);

        const update = {
            'uberDelivery.lastWebhookAt': new Date(),
            'uberDelivery.lastWebhookEventId': eventId,
            'uberDelivery.lastWebhookType': eventType,
            'uberDelivery.webhookStatus': status,
            'uberDelivery.status': normalizedStatus,
            'uberDelivery.rawWebhook': body
        };

        if (data.tracking_url || data.trackingUrl) {
            update['uberDelivery.trackingUrl'] = data.tracking_url || data.trackingUrl;
        }

        if (data.courier) {
            update['uberDelivery.courier'] = data.courier;
        }

        if (data.dropoff_eta || data.eta) {
            update['uberDelivery.eta'] = data.dropoff_eta || data.eta;
            update['uberDelivery.dropoffEta'] = data.dropoff_eta || data.eta;
        }

        if (data.pickup_eta) {
            update['uberDelivery.pickupEta'] = data.pickup_eta;
        }

        if (normalizedStatus === 'delivered') {
            update['uberDelivery.deliveredAt'] = new Date();
        }

        if (normalizedStatus === 'canceled') {
            update['uberDelivery.canceledAt'] = new Date();
        }

        const result = await app.locals.db.collection('orders').updateOne(
            filter,
            { $set: update }
        );

        console.log('✅ Webhook Uber processado:', {
            eventId,
            eventType,
            status,
            normalizedStatus,
            deliveryId,
            externalDeliveryId,
            matched: result.matchedCount,
            modified: result.modifiedCount
        });

    } catch (error) {
        console.error('❌ Erro no webhook Uber Direct:', error);
        if (!res.headersSent) {
            res.status(500).json({ error: 'Erro interno' });
        }
    }
});

function normalizeUberDeliveryStatus(status = '') {
    const s = String(status).toLowerCase();

    if (!s) return 'updated';

    if (['pending', 'created'].includes(s)) return 'created';

    if (['pickup', 'courier_assigned', 'courier_imminent'].includes(s)) {
        return 'pickup';
    }

    if (['dropoff', 'in_progress', 'en_route', 'delivering'].includes(s)) {
        return 'in_route';
    }

    if (['delivered', 'completed'].includes(s)) {
        return 'delivered';
    }

    if (['canceled', 'cancelled', 'failed'].includes(s)) {
        return 'canceled';
    }

    if (['returned', 'returning'].includes(s)) {
        return 'returned';
    }

    return s;
}

// ========== INICIAR SERVIDOR ==========
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Servidor rodando na porta ${PORT}`);
    console.log(`📡 Health: http://0.0.0.0:${PORT}/health`);
    console.log(`⚙️  Config: http://0.0.0.0:${PORT}/api/config`);
    console.log(`📋 Admin Orders: http://0.0.0.0:${PORT}/api/admin/orders`);
    console.log('='.repeat(70));

    setTimeout(initializeMongoDB, 1000);
});

module.exports = app;
