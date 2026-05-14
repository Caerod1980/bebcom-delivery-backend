// services/uberDirectService.js

const fetch = require('node-fetch');
const crypto = require('crypto');
const {
    calculateOrderWeight,
    selectVehicleByWeight
} = require('./weightCalculator');

const UBER_DIRECT_ENABLED = process.env.UBER_DIRECT_ENABLED === 'true';
const UBER_SANDBOX_MODE = process.env.UBER_SANDBOX_MODE !== 'false';

const UBER_CLIENT_ID = process.env.UBER_CLIENT_ID;
const UBER_CLIENT_SECRET = process.env.UBER_CLIENT_SECRET;
const UBER_CUSTOMER_ID = process.env.UBER_CUSTOMER_ID;

const STORE_NAME = process.env.STORE_NAME || 'Bebidas e Companhia';
const STORE_PHONE = process.env.STORE_PHONE || process.env.WHATSAPP_NUMBER || '5514996130369';

const STORE_ADDRESS = {
    street: process.env.STORE_STREET || 'R. José Henrique Ferraz',
    number: process.env.STORE_NUMBER || '18-10',
    neighborhood: process.env.STORE_NEIGHBORHOOD || 'Centro',
    city: process.env.STORE_CITY || 'Bauru',
    state: process.env.STORE_STATE || 'SP',
    country: 'BR',
    postalCode: process.env.STORE_POSTAL_CODE || ''
};

function cleanPhone(phone = '') {
    const digits = String(phone).replace(/\D/g, '');

    if (!digits) return '5514996130369';
    if (digits.startsWith('55')) return digits;

    return `55${digits}`;
}

function buildFullAddress(address = {}) {
    const street = address.street || '';
    const number = address.number || '';
    const neighborhood = address.neighborhood || '';
    const city = address.city || 'Bauru';

    if (address.fullAddress) return address.fullAddress;

    return `${street}${number ? `, ${number}` : ''}${neighborhood ? ` - ${neighborhood}` : ''}, ${city}`;
}

function createInternalTrackingUrl(orderId) {
    return `https://bebidasecompanhia.com.br/tracking/${orderId}`;
}

function validateOrderForDelivery(order) {
    if (!order) {
        throw new Error('Pedido não informado');
    }

    if (order.deliveryType !== 'delivery') {
        throw new Error('Pedido não é entrega');
    }

    if (!order.address) {
        throw new Error('Endereço de entrega ausente');
    }

    if (!order.customer || !order.customer.phone) {
        throw new Error('Dados do cliente incompletos');
    }

    if (!Array.isArray(order.items) || order.items.length === 0) {
        throw new Error('Pedido sem itens');
    }

    if (order.uberDelivery?.deliveryId) {
        throw new Error('Pedido já possui entrega Uber criada');
    }
}

async function getUberAccessToken() {
    if (!UBER_CLIENT_ID || !UBER_CLIENT_SECRET) {
        throw new Error('Credenciais Uber não configuradas');
    }

    const authUrl = 'https://auth.uber.com/oauth/v2/token';

       const response = await fetch(authUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
            client_id: UBER_CLIENT_ID,
            client_secret: UBER_CLIENT_SECRET,
            grant_type: 'client_credentials',
            scope: 'eats.deliveries'
        })
    });

    const data = await response.json();

    if (!response.ok) {
        throw new Error(`Erro OAuth Uber: ${JSON.stringify(data)}`);
    }

    return data.access_token;
}

function buildUberDeliveryPayload(order, weightInfo, vehicleInfo) {
    const customerPhone = cleanPhone(order.customer.phone);
    const dropoffAddress = buildFullAddress(order.address);

    const itemsDescription = order.items
        .map(item => `${item.quantity}x ${item.title}`)
        .join(', ');

    return {
        external_delivery_id: order.orderId,
        pickup_name: STORE_NAME,
        pickup_phone_number: `+${cleanPhone(STORE_PHONE)}`,
        pickup_address: JSON.stringify({
    street_address: [
        'Avenida José Henrique Ferraz, 18-10'
    ],
    city: 'Bauru',
    state: 'SP',
    zip_code: '17054-697',
    country: 'BR'
}),

pickup_latitude: -22.358239673270123,
pickup_longitude: -49.09889888198475,
        dropoff_name: order.customer.name,
        dropoff_phone_number: `+${customerPhone}`,
        dropoff_address: JSON.stringify({
    street_address: [
        order.address.street || order.address.fullAddress || dropoffAddress
    ],
    city: order.address.city || 'Bauru',
    state: 'SP',
    zip_code: order.address.postalCode || '',
    country: 'BR'
}),
      manifest_items: order.items.map(item => ({
    name: item.title,
    quantity: Number(item.quantity || 1),
    size: 'small',
    price: Math.round(Number(item.unit_price || 0) * 100)
})),
        manifest_reference: order.orderId,
        manifest_total_value: Math.round(Number(order.total || 0) * 100),
        pickup_notes: `Pedido ${order.orderId}. Retirar na loja Bebidas e Companhia. Conferir fachada da loja antes de retirar.`,
        dropoff_notes: order.address.complement
            ? `Complemento/referência: ${order.address.complement}`
            : 'Entregar ao cliente informado.',
        undeliverable_action: 'return',
        delivery_metadata: {
            orderId: order.orderId,
            weightKg: weightInfo.totalWeightKg,
            vehicleType: vehicleInfo.vehicleType,
            vehicleLabel: vehicleInfo.label,
            itemsDescription
        }
    };
}

async function createUberDeliveryReal(order, weightInfo, vehicleInfo) {
    const token = await getUberAccessToken();

    if (!UBER_CUSTOMER_ID) {
    console.warn('⚠️ UBER_CUSTOMER_ID ausente. Tentando Organization default.');
    }

    const payload = buildUberDeliveryPayload(order, weightInfo, vehicleInfo);

   const apiBase = 'https://api.uber.com';
    
const baseUrl = UBER_CUSTOMER_ID
    ? `${apiBase}/v1/customers/${UBER_CUSTOMER_ID}/deliveries`
    : `${apiBase}/v1/deliveries`;
    
const response = await fetch(baseUrl, {
    method: 'POST',
    headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json'
    },
    body: JSON.stringify(payload)
});

    const data = await response.json();

    if (!response.ok) {
        throw new Error(`Erro ao criar entrega Uber: ${JSON.stringify(data)}`);
    }

    return data;
}

async function createUberDeliverySimulation(order, weightInfo, vehicleInfo) {
    const fakeDeliveryId = `SIM-${crypto.randomBytes(6).toString('hex').toUpperCase()}`;

    return {
        id: fakeDeliveryId,
        external_delivery_id: order.orderId,
        status: 'simulated',
        tracking_url: createInternalTrackingUrl(order.orderId),
        fee: 0,
        currency: 'BRL',
        vehicle_type: vehicleInfo.vehicleType,
        simulated: true
    };
}

async function processUberDelivery(order, db) {
    const startedAt = new Date();

    try {
        validateOrderForDelivery(order);

        const weightInfo = calculateOrderWeight(order.items);
        const vehicleInfo = selectVehicleByWeight(weightInfo.totalWeightKg);

        console.log('🚚 Iniciando automação Uber Direct:', {
            orderId: order.orderId,
            weightKg: weightInfo.totalWeightKg,
            vehicle: vehicleInfo.label,
            enabled: UBER_DIRECT_ENABLED,
            sandbox: UBER_SANDBOX_MODE
        });

        await db.collection('orders').updateOne(
            { _id: order._id },
            {
                $set: {
                    'uberDelivery.status': 'processing',
                    'uberDelivery.weightInfo': weightInfo,
                    'uberDelivery.vehicleInfo': vehicleInfo,
                    'uberDelivery.startedAt': startedAt,
                    'uberDelivery.enabled': UBER_DIRECT_ENABLED,
                    'uberDelivery.sandbox': UBER_SANDBOX_MODE
                }
            }
        );

        let delivery;

       if (!UBER_DIRECT_ENABLED) {
          delivery = await createUberDeliverySimulation(order, weightInfo, vehicleInfo);
       } else {
          delivery = await createUberDeliveryReal(order, weightInfo, vehicleInfo);
       }

        const trackingUrl =
            delivery.tracking_url ||
            delivery.trackingUrl ||
            delivery.courier_imminent_url ||
            null;

        await db.collection('orders').updateOne(
            { _id: order._id },
            {
               $set: {
    'uberDelivery.created': true,
    'uberDelivery.status': delivery.status || 'created',
    'uberDelivery.deliveryId': delivery.id,
    'uberDelivery.trackingUrl': trackingUrl,

    // NOVO: dados operacionais para painel
    'uberDelivery.fee': delivery.fee || delivery.delivery_fee || null,
    'uberDelivery.currency': delivery.currency || 'BRL',
    'uberDelivery.courier': delivery.courier || null,
    'uberDelivery.eta': delivery.dropoff_eta || delivery.eta || null,
    'uberDelivery.pickupEta': delivery.pickup_eta || null,
    'uberDelivery.dropoffEta': delivery.dropoff_eta || null,

    'uberDelivery.raw': delivery,
    'uberDelivery.createdAt': new Date(),
    'uberDelivery.error': null
}
            }
        );

        console.log('✅ Entrega Uber processada:', {
            orderId: order.orderId,
            deliveryId: delivery.id,
            trackingUrl
        });

        return {
            success: true,
            deliveryId: delivery.id,
            trackingUrl,
            simulated: !!delivery.simulated,
            weightInfo,
            vehicleInfo
        };

    } catch (error) {
        console.error('❌ Erro na automação Uber Direct:', {
            orderId: order?.orderId,
            error: error.message
        });

        if (db && order?._id) {
            await db.collection('orders').updateOne(
                { _id: order._id },
                {
                    $set: {
                        'uberDelivery.status': 'error',
                        'uberDelivery.error': error.message,
                        'uberDelivery.failedAt': new Date()
                    }
                }
            );
        }

        return {
            success: false,
            error: error.message
        };
    }
}

module.exports = {
    processUberDelivery,
    calculateOrderWeight,
    selectVehicleByWeight
};
