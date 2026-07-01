// services/qrManager.js
const QRCode = require('qrcode');
const PDFDocument = require('pdfkit');

function safeText(value = '') {
    return String(value || '').replace(/[<>]/g, '').trim();
}

function categoryEmoji(category = '') {
    const key = String(category || '').toLowerCase();
    if (key.includes('energ')) return '⚡';
    if (key.includes('cervej')) return '🍺';
    if (key.includes('refriger')) return '🥤';
    if (key.includes('salg')) return '🥜';
    if (key.includes('drink')) return '🍹';
    if (key.includes('destil')) return '🥃';
    if (key.includes('suco')) return '🍊';
    if (key.includes('doce')) return '🍬';
    if (key.includes('merce')) return '🛒';
    if (key.includes('carv')) return '🔥';
    if (key.includes('gelo')) return '🧊';
    return '🎮';
}

async function generateQrSvg(payload) {
    return await QRCode.toString(payload, {
        type: 'svg',
        errorCorrectionLevel: 'H',
        margin: 1,
        width: 512,
        color: { dark: '#111111', light: '#FFFFFF' }
    });
}

async function generateQrPngBuffer(payload, width = 900) {
    return await QRCode.toBuffer(payload, {
        type: 'png',
        errorCorrectionLevel: 'H',
        margin: 2,
        width,
        color: { dark: '#111111', light: '#FFFFFF' }
    });
}

function drawRoundedRect(doc, x, y, w, h, r) {
    doc.moveTo(x + r, y)
        .lineTo(x + w - r, y)
        .quadraticCurveTo(x + w, y, x + w, y + r)
        .lineTo(x + w, y + h - r)
        .quadraticCurveTo(x + w, y + h, x + w - r, y + h)
        .lineTo(x + r, y + h)
        .quadraticCurveTo(x, y + h, x, y + h - r)
        .lineTo(x, y + r)
        .quadraticCurveTo(x, y, x + r, y)
        .closePath();
}

function drawQrCard(doc, qr, x, y, w, h, qrPngBuffer) {
    const product = safeText(qr.product || 'Produto participante');
    const category = safeText(qr.category || 'Universo Bebcom');
    const adminCode = safeText(qr.adminCode || '');
    const xp = Number(qr.xp || 0);

    doc.save();
    drawRoundedRect(doc, x, y, w, h, 14);
    doc.fill('#0b0b0f');
    doc.restore();

    doc.save();
    drawRoundedRect(doc, x, y, w, h, 14);
    doc.lineWidth(1.4).stroke('#dc2626');
    doc.restore();

    doc.save();
    drawRoundedRect(doc, x + 8, y + 8, w - 16, 28, 9);
    doc.fill('#15151c');
    doc.restore();

    doc.font('Helvetica-Bold').fontSize(8.5).fillColor('#f59e0b')
        .text('UNIVERSO BEBCOM', x + 12, y + 16, { width: w - 24, align: 'center' });

    doc.font('Helvetica-Bold').fontSize(product.length > 22 ? 13 : 16).fillColor('#ffffff')
        .text(product.substring(0, 34), x + 12, y + 43, { width: w - 24, align: 'center' });

    doc.font('Helvetica').fontSize(8).fillColor('#cbd5e1')
        .text(`${categoryEmoji(category)} Produto participante`, x + 12, y + 65, { width: w - 24, align: 'center' });

    const qrSize = Math.min(w - 50, h * 0.43);
    const qrX = x + (w - qrSize) / 2;
    const qrY = y + 82;

    doc.save();
    drawRoundedRect(doc, qrX - 8, qrY - 8, qrSize + 16, qrSize + 16, 12);
    doc.fill('#ffffff');
    doc.restore();

    doc.image(qrPngBuffer, qrX, qrY, { width: qrSize, height: qrSize });

    const ctaY = qrY + qrSize + 18;

    doc.font('Helvetica-Bold').fontSize(11).fillColor('#f59e0b')
        .text('ESCANEIE E GANHE XP', x + 12, ctaY, { width: w - 24, align: 'center' });

    doc.font('Helvetica').fontSize(8).fillColor('#e5e7eb')
        .text('Compre, escaneie e avance nas campanhas do Clube Bebcom.', x + 12, ctaY + 15, { width: w - 24, align: 'center' });

    doc.save();
    drawRoundedRect(doc, x + 12, y + h - 34, w - 24, 22, 8);
    doc.fill('#171722');
    doc.restore();

    doc.font('Helvetica-Bold').fontSize(7).fillColor('#94a3b8')
        .text(`${adminCode}${xp ? ` • ${xp} XP` : ''}`, x + 18, y + h - 27, { width: w - 36, align: 'center' });
}

async function generateQrPdfBuffer(qrs = [], options = {}) {
    const items = Array.isArray(qrs) ? qrs.filter(Boolean) : [];
    if (!items.length) throw new Error('Nenhum QR informado para PDF');

    const doc = new PDFDocument({
        size: 'A4',
        margin: 24,
        info: { Title: 'QR Codes Loja Física — Clube Bebcom', Author: 'Bebidas & Companhia' }
    });

    const chunks = [];
    doc.on('data', chunk => chunks.push(chunk));

    const done = new Promise((resolve, reject) => {
        doc.on('end', () => resolve(Buffer.concat(chunks)));
        doc.on('error', reject);
    });

    const pageW = doc.page.width;
    const pageH = doc.page.height;
    const margin = 24;

    doc.font('Helvetica-Bold').fontSize(18).fillColor('#111111')
        .text('QR Codes — Loja Física', margin, 22, { width: pageW - margin * 2, align: 'center' });

    doc.font('Helvetica').fontSize(9).fillColor('#555555')
        .text('Clube Bebcom • Bebidas & Companhia', margin, 45, { width: pageW - margin * 2, align: 'center' });

    const cols = Number(options.cols || 2);
    const gap = 14;
    const cardW = (pageW - margin * 2 - gap * (cols - 1)) / cols;
    const cardH = Number(options.cardH || 230);
    let x = margin;
    let y = 70;

    for (let i = 0; i < items.length; i++) {
        const qr = items[i];

        if (y + cardH > pageH - 28) {
            doc.addPage();
            y = 40;
            x = margin;
        }

        const qrPng = await generateQrPngBuffer(qr.qrPayload, 700);
        drawQrCard(doc, qr, x, y, cardW, cardH, qrPng);

        x += cardW + gap;

        if ((i + 1) % cols === 0) {
            x = margin;
            y += cardH + gap;
        }
    }

    doc.end();
    return await done;
}

async function generateSingleQrPdfBuffer(qr) {
    return await generateQrPdfBuffer([qr], { cols: 1, cardH: 360 });
}

module.exports = {
    generateQrSvg,
    generateQrPngBuffer,
    generateQrPdfBuffer,
    generateSingleQrPdfBuffer
};
