const express = require('express');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const validator = require('validator');
const xss = require('xss');
require('dotenv').config();

const app = express();

// Безопасность
app.use(helmet());
app.use(express.json({ limit: '10mb' }));

// CORS настройки - укажите свой домен
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
  credentials: true,
  optionsSuccessStatus: 200
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 минут
  max: 5, // максимум 5 запросов с одного IP за 15 минут
  message: {
    error: 'Слишком много запросов, попробуйте позже'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Дополнительный лимит для отправки сообщений
const submitLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 час
  max: 3, // максимум 3 заявки в час с одного IP
  message: {
    error: 'Превышен лимит заявок. Попробуйте через час.'
  }
});

app.use('/api/', limiter);

// Валидация данных
const validateSubmissionData = (data) => {
  const errors = [];
  
  // Проверка имени
  if (!data.name || typeof data.name !== 'string') {
    errors.push('Имя обязательно для заполнения');
  } else if (data.name.length < 2 || data.name.length > 50) {
    errors.push('Имя должно быть от 2 до 50 символов');
  } else if (!/^[a-zA-Zа-яА-ЯёЁ\s-]+$/.test(data.name)) {
    errors.push('Имя содержит недопустимые символы');
  }
  
  // Проверка телефона
  if (!data.phone || typeof data.phone !== 'string') {
    errors.push('Номер телефона обязателен');
  } else {
    // Очистка номера от всех символов кроме цифр и +
    const cleanPhone = data.phone.replace(/[^\d+]/g, '');
    if (!validator.isMobilePhone(cleanPhone, 'any', { strictMode: false })) {
      errors.push('Некорректный номер телефона');
    }
  }
  
  // Проверка адреса
  if (!data.address || typeof data.address !== 'string') {
    errors.push('Адрес обязателен для заполнения');
  } else if (data.address.length < 5 || data.address.length > 200) {
    errors.push('Адрес должен быть от 5 до 200 символов');
  }
  
  // Проверка тарифа
//   const allowedTariffs = ['Базовый', 'Стандарт', 'Премиум', 'Корпоративный'];
//   if (!data.selectedTariff || !allowedTariffs.includes(data.selectedTariff)) {
  if (!data.selectedTariff) {
    errors.push('Выберите корректный тариф');
  }
  
  // Проверка комментария (опционально)
  if (data.comment && typeof data.comment === 'string' && data.comment.length > 500) {
    errors.push('Комментарий не должен превышать 500 символов');
  }
  
  return errors;
};

// Очистка данных от XSS
const sanitizeData = (data) => {
  return {
    name: xss(data.name?.trim()),
    phone: xss(data.phone?.trim()),
    address: xss(data.address?.trim()),
    selectedTariff: xss(data.selectedTariff?.trim()),
    comment: data.comment ? xss(data.comment.trim()) : ''
  };
};

// Отправка в Telegram
const sendToTelegram = async (data) => {
  const botToken = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  
  if (!botToken || !chatId) {
    throw new Error('Telegram credentials not configured');
  }
  
  const message = `
📥 Новая заявка на подключение:
👤 Имя: ${data.name}
📱 Номер: ${data.phone}
🏠 Адрес: ${data.address}
📶 Тариф: ${data.selectedTariff}
📝 Комментарий: ${data.comment || "Нет"}
🕐 Время: ${new Date().toLocaleString('ru-RU')}
  `.trim();

  const response = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      chat_id: chatId,
      text: message,
      parse_mode: 'HTML'
    }),
  });

  if (!response.ok) {
    const errorData = await response.json();
    throw new Error(`Telegram API error: ${errorData.description || 'Unknown error'}`);
  }

  return await response.json();
};

// Основной эндпоинт
app.post('/api/submit-application', submitLimiter, async (req, res) => {
  try {
    // Валидация данных
    const validationErrors = validateSubmissionData(req.body);
    if (validationErrors.length > 0) {
      return res.status(400).json({
        success: false,
        error: 'Ошибка валидации данных',
        details: validationErrors
      });
    }

    // Очистка данных
    const sanitizedData = sanitizeData(req.body);

    // Отправка в Telegram
    await sendToTelegram(sanitizedData);

    // Логирование (без чувствительных данных)
    console.log(`[${new Date().toISOString()}] Application submitted successfully for ${sanitizedData.name}`);

    res.json({
      success: true,
      message: 'Заявка успешно отправлена!'
    });

  } catch (error) {
    console.error(`[${new Date().toISOString()}] Error processing application:`, error.message);
    
    res.status(500).json({
      success: false,
      error: 'Произошла ошибка при отправке заявки. Попробуйте позже.'
    });
  }
});

app.post('/api/request-callback', async (req, res) => {
    const { phone } = req.body;
  
    if (!phone || typeof phone !== 'string' || phone.replace(/[^\d]/g, '').length < 9) {
      return res.status(400).json({
        success: false,
        error: 'Введите корректный номер телефона'
      });
    }
  
    const sanitizedPhone = xss(phone.trim());
  
    const botToken = process.env.TELEGRAM_BOT_TOKEN;
    const chatId = process.env.TELEGRAM_CHAT_ID;
  
    if (!botToken || !chatId) {
      return res.status(500).json({
        success: false,
        error: 'Не настроены Telegram данные'
      });
    }
  
    const message = `📞 Новый запрос на звонок!\n\nТелефон: ${sanitizedPhone}`;
  
    try {
      const response = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: chatId,
          text: message
        })
      });
  
      if (!response.ok) {
        console.log("send");
        const errorData = await response.json();
        throw new Error(`Telegram API error: ${errorData.description}`);
      }
      console.log("send");
  
      res.json({ success: true, message: 'Заявка отправлена!' });
    } catch (error) {
      console.error('Telegram send error:', error.message);
      res.status(500).json({
        success: false,
        error: 'Ошибка при отправке в Telegram'
      });
    }
  });
  
  app.post('/api/request-ngn-callback', async (req, res) => {
    const { phone, selectedTariff } = req.body;
  
    // Валидация
    if (!phone || typeof phone !== 'string' || phone.replace(/[^\d]/g, '').length < 9) {
      return res.status(400).json({
        success: false,
        error: 'Введите корректный номер телефона',
      });
    }
  
    if (!selectedTariff || typeof selectedTariff !== 'string') {
      return res.status(400).json({
        success: false,
        error: 'Выберите тариф',
      });
    }
  
    // Очистка
    const sanitizedPhone = xss(phone.trim());
    const sanitizedTariff = xss(selectedTariff.trim());
  
    const botToken = process.env.TELEGRAM_BOT_TOKEN;
    const chatId = process.env.TELEGRAM_CHAT_ID;
  
    if (!botToken || !chatId) {
      return res.status(500).json({
        success: false,
        error: 'Telegram токен или ID не настроены',
      });
    }
  
    const message = `
  📞 Заявка на обратный звонок NGN!
  📱 Номер: ${sanitizedPhone}
  📌 Тариф: ${sanitizedTariff}
  🕐 Время: ${new Date().toLocaleString('ru-RU')}
  `.trim();
  
    try {
      const tgRes = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: chatId,
          text: message,
          parse_mode: 'HTML',
        }),
      });
  
      if (!tgRes.ok) {
        const err = await tgRes.json();
        throw new Error(err.description || 'Telegram API error');
      }
  
      res.json({ success: true, message: 'Заявка отправлена' });
    } catch (error) {
      console.error('Ошибка Telegram:', error.message);
      res.status(500).json({
        success: false,
        error: 'Ошибка при отправке в Telegram',
      });
    }
  });
  

  app.post('/api/request-wimax', async (req, res) => {
    const { name, phone } = req.body;
  
    // Валидация
    if (!name || typeof name !== 'string' || name.length < 2 || name.length > 50) {
      return res.status(400).json({ success: false, error: 'Введите корректное имя' });
    }
  
    if (!phone || typeof phone !== 'string' || phone.replace(/[^\d]/g, '').length < 9) {
      return res.status(400).json({ success: false, error: 'Введите корректный номер телефона' });
    }
  
    // Очистка
    const cleanName = xss(name.trim());
    const cleanPhone = xss(phone.trim());
  
    const botToken = process.env.TELEGRAM_BOT_TOKEN;
    const chatId = process.env.TELEGRAM_CHAT_ID;
  
    if (!botToken || !chatId) {
      return res.status(500).json({
        success: false,
        error: 'Telegram токен или ID не настроены'
      });
    }
  
    const message = `
  ✉️ Новый запрос WiMAX!
  👤 Имя: ${cleanName}
  ☎️ Телефон: ${cleanPhone}
  🕐 Время: ${new Date().toLocaleString('ru-RU')}
  `.trim();
  
    try {
      const tgRes = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: chatId,
          text: message,
          parse_mode: 'HTML',
        }),
      });
  
      if (!tgRes.ok) {
        const err = await tgRes.json();
        throw new Error(err.description || 'Telegram API error');
      }
  
      res.json({ success: true, message: 'Заявка отправлена' });
    } catch (error) {
      console.error('Ошибка Telegram:', error.message);
      res.status(500).json({
        success: false,
        error: 'Ошибка при отправке в Telegram'
      });
    }
  });
  

  app.post('/api/submit-connection-request', async (req, res) => {
    const { name, phone, address, comment, tariff } = req.body;
  
    const errors = [];
  
    if (!name || typeof name !== 'string' || name.length < 2 || name.length > 50) {
      errors.push('Некорректное имя');
    }
    if (!phone || typeof phone !== 'string' || phone.replace(/[^\d]/g, '').length < 9) {
      errors.push('Некорректный номер телефона');
    }
    if (!address || typeof address !== 'string' || address.length < 5 || address.length > 200) {
      errors.push('Некорректный адрес');
    }
    if (!tariff || typeof tariff !== 'string') {
      errors.push('Тариф не выбран');
    }
    if (comment && typeof comment === 'string' && comment.length > 500) {
      errors.push('Комментарий слишком длинный');
    }
  
    if (errors.length > 0) {
      return res.status(400).json({
        success: false,
        error: 'Ошибка валидации данных',
        details: errors,
      });
    }
  
    const cleanData = {
      name: xss(name.trim()),
      phone: xss(phone.trim()),
      address: xss(address.trim()),
      tariff: xss(tariff.trim()),
      comment: comment ? xss(comment.trim()) : 'нет',
    };
  
    const botToken = process.env.TELEGRAM_BOT_TOKEN;
    const chatId = process.env.TELEGRAM_CHAT_ID;
  
    if (!botToken || !chatId) {
      return res.status(500).json({
        success: false,
        error: 'Telegram токен или чат-ID не настроены',
      });
    }
  
    const message = `
  📥 Новая заявка на подключение:
  👤 Имя: ${cleanData.name}
  📱 Номер: ${cleanData.phone}
  🏠 Адрес: ${cleanData.address}
  📶 Тариф: ${cleanData.tariff}
  📝 Комментарий: ${cleanData.comment}
  🕐 Время: ${new Date().toLocaleString('ru-RU')}
  `.trim();
  
    try {
      const response = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: chatId,
          text: message,
          parse_mode: 'HTML',
        }),
      });
  
      if (!response.ok) {
        const err = await response.json();
        throw new Error(err.description || 'Ошибка Telegram API');
      }
  
      res.json({ success: true, message: 'Заявка отправлена' });
    } catch (error) {
      console.error('Ошибка Telegram:', error.message);
      res.status(500).json({ success: false, error: 'Ошибка отправки в Telegram' });
    }
  });
   

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Error handler
app.use((error, req, res, next) => {
  console.error(`[${new Date().toISOString()}] Unhandled error:`, error);
  res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3001;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

module.exports = app;