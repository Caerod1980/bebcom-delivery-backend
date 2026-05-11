// services/weightCalculator.js

function normalizeText(text = '') {
    return String(text)
        .toLowerCase()
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '');
}

function calculateOrderWeight(items = []) {
    let totalWeightKg = 0;
    const details = [];

    for (const item of items) {
        const title = normalizeText(item.title || item.name || '');
        const quantity = Number(item.quantity || 1);

        let unitWeightKg = 0;
        let rule = 'sem_regra';

        if (title.includes('gelo')) {
            unitWeightKg = 4;
            rule = 'gelo_4kg';
        } else if (title.includes('carvao') || title.includes('carvão')) {
            unitWeightKg = 3;
            rule = 'carvao_3kg';
        } else if (title.includes('2l')) {
            unitWeightKg = 2.15;
            rule = 'refrigerante_2l';
        } else if (title.includes('long')) {
            unitWeightKg = 0.54;
            rule = 'long_neck';
        } else if (
            title.includes('cerveja') ||
            title.includes('brahma') ||
            title.includes('skol') ||
            title.includes('antarctica') ||
            title.includes('amstel') ||
            title.includes('heineken') ||
            title.includes('imperio') ||
            title.includes('império') ||
            title.includes('budweiser') ||
            title.includes('spaten') ||
            title.includes('petra') ||
            title.includes('original') ||
            title.includes('conti') ||
            title.includes('bavaria') ||
            title.includes('burguesa') ||
            title.includes('michelob') ||
            title.includes('eisenbah')
        ) {
            unitWeightKg = 0.37;
            rule = 'cerveja_lata';
        }
if (unitWeightKg === 0) {
    unitWeightKg = 0.5;
    rule = 'fallback_default';
}
        const totalItemWeight = unitWeightKg * quantity;
        totalWeightKg += totalItemWeight;

        details.push({
            title: item.title,
            quantity,
            unitWeightKg,
            totalItemWeight,
            rule
        });
    }

    return {
        totalWeightKg: Number(totalWeightKg.toFixed(3)),
        details
    };
}

function selectVehicleByWeight(weightKg) {
    if (weightKg <= 10) {
        return {
            vehicleType: 'motorcycle',
            label: 'Moto',
            reason: 'Peso até 10kg'
        };
    }

    return {
        vehicleType: 'car',
        label: 'Carro',
        reason: 'Peso acima de 10kg'
    };
}

module.exports = {
    calculateOrderWeight,
    selectVehicleByWeight
};
