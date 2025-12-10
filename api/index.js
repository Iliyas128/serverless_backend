const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');

// Загружаем переменные окружения из .env
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
let cachedClient = null;
let cachedDb = null;

async function connectToDatabase() {
  if (cachedClient && cachedDb) {
    return { client: cachedClient, db: cachedDb };
  }

  const client = await MongoClient.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });

  const db = client.db(process.env.DB_NAME || 'Shop');
  
  cachedClient = client;
  cachedDb = db;

  return { client, db };
}

// Константы коллекций
const COLLECTION_NAME = 'Data';
const CATEGORIES_COLLECTION = 'Categories';
const ADMIN_USERS_COLLECTION = 'AdminUsers';
const ADMIN_OTPS_COLLECTION = 'AdminOtps';

// Настройки auth/OTP
const ADMIN_MASTER_EMAIL = process.env.ADMIN_MASTER_EMAIL || 'Weking128@gmail.com';
const JWT_SECRET = process.env.JWT_SECRET || 'change-me';
const OTP_EXP_MINUTES = parseInt(process.env.OTP_EXP_MINUTES || '10', 10);
const OTP_LENGTH = parseInt(process.env.OTP_LENGTH || '6', 10);
const PASSWORD_MIN_LEN = parseInt(process.env.ADMIN_PASSWORD_MIN_LEN || '6', 10);

// Nodemailer
let mailerReady = false;
let transporter = null;
if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '587', 10),
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });
  mailerReady = true;
} else {
  console.warn('SMTP env not configured; OTP codes will be logged to console only.');
}

function generateOtp(length = OTP_LENGTH) {
  const min = Math.pow(10, length - 1);
  const max = Math.pow(10, length) - 1;
  return Math.floor(min + Math.random() * (max - min)).toString();
}

async function sendOtpEmail(code) {
  const to = ADMIN_MASTER_EMAIL;
  const subject = 'SUPRA TRADE Admin OTP';
  const text = `Ваш код для входа/регистрации администратора: ${code}\nДействует ${OTP_EXP_MINUTES} минут.`;

  if (!mailerReady) {
    console.log(`[DEV OTP] ${code} -> ${to}`);
    return;
  }

  await transporter.sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to,
    subject,
    text,
  });
}

async function ensurePasswordValid(password) {
  if (!password || typeof password !== 'string' || password.length < PASSWORD_MIN_LEN) {
    const msg = `Пароль обязателен и должен быть не короче ${PASSWORD_MIN_LEN} символов`;
    throw new Error(msg);
  }
}

// Middleware для защиты админских маршрутов
function requireAdminAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) {
    return res.status(401).json({ success: false, error: 'Нет токена' });
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.admin = { email: payload.email };
    next();
  } catch (err) {
    return res.status(401).json({ success: false, error: 'Неверный или просроченный токен' });
  }
}

// === Utilities ===
const RU_MAP = {
  а: 'a', б: 'b', в: 'v', г: 'g', д: 'd', е: 'e', ё: 'e', ж: 'zh', з: 'z',
  и: 'i', й: 'y', к: 'k', л: 'l', м: 'm', н: 'n', о: 'o', п: 'p', р: 'r',
  с: 's', т: 't', у: 'u', ф: 'f', х: 'h', ц: 'c', ч: 'ch', ш: 'sh', щ: 'shch',
  ы: 'y', э: 'e', ю: 'yu', я: 'ya', ь: '', ъ: '',
};

function transliterate(str = '') {
  return String(str)
    .split('')
    .map(ch => {
      const lower = ch.toLowerCase();
      const mapped = RU_MAP[lower];
      if (mapped !== undefined) return mapped;
      return lower.match(/[a-z0-9]/) ? lower : '-';
    })
    .join('');
}

function slugify(text = '') {
  return transliterate(text)
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/--+/g, '-')
    .replace(/^-+|-+$/g, '')
    || 'item';
}

function normalizeSlug(slug = '') {
  return slugify(slug || '');
}

function generateProductFullUrl(product) {
  const productSlug = String(product.url || '').replace(/^\/?catalog\//, '').replace(/^\/+|\/+$/g, '');

  // Новый формат: categoryFullSlug + productSlug
  if (product.categoryFullSlug) {
    return `/catalog/${product.categoryFullSlug}/${productSlug}`;
  }

  // Fallback на старый формат категорий
  if (product.categories && product.categories.length > 0) {
  const slugs = product.categories
    .filter(cat => cat.slug)
    .map(cat => cat.slug)
    .join('/');
  return `/catalog/${slugs}/${productSlug}`;
}

  return `/catalog/${productSlug}`;
}

function enrichProductData(product) {
  return {
    ...product,
    fullUrl: generateProductFullUrl(product)
  };
}

async function getCategoryById(db, id) {
  if (!id || !ObjectId.isValid(id)) {
    return null;
  }
  return db.collection(CATEGORIES_COLLECTION).findOne({ _id: new ObjectId(id) });
}

async function buildCategoryPath(db, categoryId) {
  const categoriesCol = db.collection(CATEGORIES_COLLECTION);
  const path = [];

  let currentId = categoryId;
  const safety = 30; // защитный лимит глубины
  for (let i = 0; i < safety && currentId; i++) {
    const doc = await categoriesCol.findOne({ _id: new ObjectId(currentId) });
    if (!doc) break;
    path.unshift({
      _id: doc._id,
      name: doc.name,
      slug: doc.slug,
    });
    currentId = doc.parentId ? doc.parentId.toString() : null;
  }

  const fullSlug = path.map(p => p.slug).join('/');
  return { path, fullSlug };
}

async function ensureCategoryAttachment(db, categoryId) {
  const category = await getCategoryById(db, categoryId);
  if (!category) {
    throw new Error('Категория не найдена');
  }
  const { path, fullSlug } = await buildCategoryPath(db, category._id);
  return {
    categoryId: category._id,
    categoryPath: path,
    categoryFullSlug: fullSlug,
  };
}

function buildCategoriesTree(list) {
  const byId = new Map();
  const roots = [];

  list.forEach(cat => {
    const node = { ...cat, children: [] };
    byId.set(String(cat._id), node);
  });

  byId.forEach(node => {
    if (node.parentId) {
      const parent = byId.get(String(node.parentId));
      if (parent) {
        parent.children.push(node);
      } else {
        roots.push(node);
      }
    } else {
      roots.push(node);
    }
  });

  const sortRecursive = (arr) => {
    arr.sort((a, b) => {
      const orderA = a.order ?? 0;
      const orderB = b.order ?? 0;
      if (orderA !== orderB) return orderA - orderB;
      return (a.name || '').localeCompare(b.name || '');
    });
    arr.forEach(child => sortRecursive(child.children));
  };

  sortRecursive(roots);
  return roots;
}

// API Routes

// === Admin auth (OTP + JWT) ===
app.post('/api/admin/request-otp', async (req, res) => {
  try {
    const email = (req.body?.email || '').trim().toLowerCase();
    if (!email) {
      return res.status(400).json({ success: false, error: 'Email обязателен' });
    }

    const code = generateOtp();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + OTP_EXP_MINUTES * 60 * 1000);

    const { db } = await connectToDatabase();
    const otpCollection = db.collection(ADMIN_OTPS_COLLECTION);

    await otpCollection.insertOne({
      email,
      code,
      createdAt: now,
      expiresAt,
      used: false,
    });

    await sendOtpEmail(code);

    return res.json({ success: true });
  } catch (error) {
    console.error('Error requesting OTP:', error);
    return res.status(500).json({ success: false, error: 'Ошибка при отправке кода' });
  }
});

app.post('/api/admin/verify-otp', async (req, res) => {
  try {
    const email = (req.body?.email || '').trim().toLowerCase();
    const code = (req.body?.code || '').trim();
    const password = req.body?.password;

    if (!email || !code || !password) {
      return res.status(400).json({ success: false, error: 'Email, код и пароль обязательны' });
    }

    try {
      await ensurePasswordValid(password);
    } catch (err) {
      return res.status(400).json({ success: false, error: err.message });
    }

    const { db } = await connectToDatabase();
    const otpCollection = db.collection(ADMIN_OTPS_COLLECTION);

    const now = new Date();
    const otp = await otpCollection.findOne({
      email,
      code,
      used: false,
      expiresAt: { $gt: now },
    });

    if (!otp) {
      return res.status(400).json({ success: false, error: 'Код неверен или истёк' });
    }

    await otpCollection.updateOne({ _id: otp._id }, { $set: { used: true } });

    const adminUsers = db.collection(ADMIN_USERS_COLLECTION);
    const existing = await adminUsers.findOne({ email });

    if (existing) {
      const ok = await bcrypt.compare(password, existing.hashedPassword || '');
      if (!ok) {
        return res.status(401).json({ success: false, error: 'Неверный пароль' });
      }
      await adminUsers.updateOne(
        { _id: existing._id },
        { $set: { updatedAt: now } },
      );
    } else {
      const hashedPassword = await bcrypt.hash(password, 10);
      await adminUsers.insertOne({
        email,
        hashedPassword,
        createdAt: now,
        updatedAt: now,
      });
    }

    const expiresInSec = 60 * 60 * 24 * 7; // 7 дней
    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: expiresInSec });

    return res.json({
      success: true,
      token,
      expiresIn: expiresInSec,
      user: { email },
    });
  } catch (error) {
    console.error('Error verifying OTP:', error);
    return res.status(500).json({ success: false, error: 'Ошибка при проверке кода' });
  }
});

// === Admin CRUD для категорий ===
app.post('/api/admin/categories', requireAdminAuth, async (req, res) => {
  try {
    const { db } = await connectToDatabase();
    const categories = db.collection(CATEGORIES_COLLECTION);

    const name = (req.body?.name || '').trim();
    const parentIdRaw = req.body?.parentId || null;
    const order = Number.isFinite(req.body?.order) ? req.body.order : 0;
    let slug = normalizeSlug(req.body?.slug || name);

    if (!name) {
      return res.status(400).json({ success: false, error: 'Название обязательно' });
    }

    const parentId = parentIdRaw && ObjectId.isValid(parentIdRaw) ? new ObjectId(parentIdRaw) : null;

    const exists = await categories.findOne({ parentId: parentId || null, slug });
    if (exists) {
      return res.status(400).json({ success: false, error: 'Slug уже занят в этой ветке' });
    }

    const now = new Date();
    const doc = {
      name,
      slug,
      parentId,
      order,
      image: req.body?.image ? String(req.body.image).trim() : undefined,
      createdAt: now,
      updatedAt: now,
    };

    const result = await categories.insertOne(doc);
    const inserted = await categories.findOne({ _id: result.insertedId });

    res.status(201).json({ success: true, category: inserted });
  } catch (error) {
    console.error('Error creating category:', error);
    res.status(500).json({ success: false, error: 'Ошибка при создании категории' });
  }
});

app.get('/api/admin/categories/tree', requireAdminAuth, async (req, res) => {
  try {
    const { db } = await connectToDatabase();
    const categories = await db
      .collection(CATEGORIES_COLLECTION)
      .find({})
      .sort({ order: 1, name: 1 })
      .toArray();

    const tree = buildCategoriesTree(categories);
    res.json({ success: true, tree });
  } catch (error) {
    console.error('Error fetching category tree (admin):', error);
    res.status(500).json({ success: false, error: 'Ошибка при получении категорий' });
  }
});

app.patch('/api/admin/categories/:id', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, error: 'Неверный ID' });
    }

    const { db } = await connectToDatabase();
    const categories = db.collection(CATEGORIES_COLLECTION);

    const payload = req.body || {};
    const updates = {};

    if (payload.name !== undefined) {
      const name = String(payload.name || '').trim();
      if (!name) return res.status(400).json({ success: false, error: 'Название обязательно' });
      updates.name = name;
      if (!payload.slug) {
        updates.slug = normalizeSlug(name);
      }
    }
    if (payload.slug !== undefined) {
      updates.slug = normalizeSlug(payload.slug);
    }
    if (payload.order !== undefined) {
      updates.order = Number.isFinite(payload.order) ? payload.order : 0;
    }
    if (payload.image !== undefined) {
      updates.image = payload.image ? String(payload.image).trim() : undefined;
    }
    if (payload.parentId !== undefined) {
      if (payload.parentId === null || payload.parentId === '') {
        updates.parentId = null;
      } else if (ObjectId.isValid(payload.parentId)) {
        updates.parentId = new ObjectId(payload.parentId);
      } else {
        return res.status(400).json({ success: false, error: 'Неверный parentId' });
      }
    }

    // Проверка уникальности slug в ветке
    if (updates.slug !== undefined || updates.parentId !== undefined) {
      const current = await categories.findOne({ _id: new ObjectId(id) });
      if (!current) return res.status(404).json({ success: false, error: 'Категория не найдена' });
      const parentId = updates.parentId !== undefined ? updates.parentId : current.parentId || null;
      const slug = updates.slug !== undefined ? updates.slug : current.slug;
      const conflict = await categories.findOne({
        _id: { $ne: new ObjectId(id) },
        parentId: parentId || null,
        slug,
      });
      if (conflict) {
        return res.status(400).json({ success: false, error: 'Slug уже занят в этой ветке' });
      }
    }

    updates.updatedAt = new Date();

    const result = await categories.findOneAndUpdate(
      { _id: new ObjectId(id) },
      { $set: updates },
      { returnDocument: 'after' },
    );

    if (!result.value) {
      return res.status(404).json({ success: false, error: 'Категория не найдена' });
    }

    res.json({ success: true, category: result.value });
  } catch (error) {
    console.error('Error updating category:', error);
    res.status(500).json({ success: false, error: 'Ошибка при обновлении категории' });
  }
});

app.delete('/api/admin/categories/:id', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, error: 'Неверный ID' });
    }

    const { db } = await connectToDatabase();
    const categories = db.collection(CATEGORIES_COLLECTION);
    const products = db.collection(COLLECTION_NAME);

    const category = await categories.findOne({ _id: new ObjectId(id) });
    if (!category) {
      return res.status(404).json({ success: false, error: 'Категория не найдена' });
    }

    const childrenCount = await categories.countDocuments({ parentId: new ObjectId(id) });
    if (childrenCount > 0) {
      return res.status(400).json({ success: false, error: 'Сперва удалите/перенесите подкатегории' });
    }

    const productsCount = await products.countDocuments({ categoryId: new ObjectId(id) });
    if (productsCount > 0) {
      return res.status(400).json({ success: false, error: 'Сперва удалите товары этой категории' });
    }

    await categories.deleteOne({ _id: new ObjectId(id) });
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting category:', error);
    res.status(500).json({ success: false, error: 'Ошибка при удалении категории' });
  }
});

// === Admin CRUD для товаров ===
app.get('/api/admin/products', requireAdminAuth, async (req, res) => {
  try {
    const { db } = await connectToDatabase();
    const collection = db.collection(COLLECTION_NAME);

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    const q = (req.query.q || '').trim();

    const searchFilter = q
      ? {
          $or: [
            { short_title: { $regex: q, $options: 'i' } },
            { full_title: { $regex: q, $options: 'i' } },
            { description: { $regex: q, $options: 'i' } },
            { tags: { $regex: q, $options: 'i' } },
            { url: { $regex: q, $options: 'i' } },
            { categoryFullSlug: { $regex: q, $options: 'i' } },
            { 'categoryPath.name': { $regex: q, $options: 'i' } },
            { 'categoryPath.slug': { $regex: q, $options: 'i' } },
          ],
        }
      : {};

    const products = await collection
      .find(searchFilter)
      .skip(skip)
      .limit(limit)
      .sort({ updatedAt: -1, createdAt: -1 })
      .project({
        _id: 1,
        short_title: 1,
        full_title: 1,
        description: 1,
        small_image: 1,
        big_images: 1,
        categoryId: 1,
        categoryPath: 1,
        categoryFullSlug: 1,
        tags: 1,
        url: 1,
        characteristics: 1,
        createdAt: 1,
        updatedAt: 1,
      })
      .toArray();

    const total = await collection.countDocuments(searchFilter);

    res.json({
      success: true,
      page,
      total,
      totalPages: Math.ceil(total / limit),
      products: products.map(enrichProductData),
    });
  } catch (error) {
    console.error('Error fetching admin products:', error);
    res.status(500).json({ success: false, error: 'Ошибка при получении товаров' });
  }
});

app.post('/api/admin/products', requireAdminAuth, async (req, res) => {
  try {
    const payload = req.body || {};
    const categoryIdRaw = payload.categoryId;
    if (!categoryIdRaw || !ObjectId.isValid(categoryIdRaw)) {
      return res.status(400).json({ success: false, error: 'categoryId обязателен' });
    }

    const { db } = await connectToDatabase();
    const collection = db.collection(COLLECTION_NAME);

    const categoryAttachment = await ensureCategoryAttachment(db, categoryIdRaw);

    const now = new Date();
    const productSlug = normalizeSlug(payload.url || payload.short_title || payload.full_title || 'product');

    const doc = {
      ...payload,
      url: productSlug,
      categoryId: categoryAttachment.categoryId,
      categoryPath: categoryAttachment.categoryPath,
      categoryFullSlug: categoryAttachment.categoryFullSlug,
      categories: undefined, // убираем старый формат
      createdAt: now,
      updatedAt: now,
    };

    const result = await collection.insertOne(doc);
    const inserted = await collection.findOne({ _id: result.insertedId });

    res.status(201).json({ success: true, product: enrichProductData(inserted) });
  } catch (error) {
    console.error('Error creating product:', error);
    res.status(500).json({ success: false, error: 'Ошибка при создании товара' });
  }
});

app.patch('/api/admin/products/:id', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const update = { ...(req.body || {}) };

    const { db } = await connectToDatabase();
    const collection = db.collection(COLLECTION_NAME);

    if (update.url) {
      update.url = normalizeSlug(update.url);
    }

    if (update.categoryId) {
      if (!ObjectId.isValid(update.categoryId)) {
        return res.status(400).json({ success: false, error: 'Неверный categoryId' });
      }
      const attachment = await ensureCategoryAttachment(db, update.categoryId);
      update.categoryId = attachment.categoryId;
      update.categoryPath = attachment.categoryPath;
      update.categoryFullSlug = attachment.categoryFullSlug;
    }

    delete update.categories; // старый формат не поддерживаем
    update.updatedAt = new Date();

    const filter = /^[a-fA-F0-9]{24}$/.test(id) ? { _id: new ObjectId(id) } : { url: id };

    const result = await collection.findOneAndUpdate(
      filter,
      { $set: update },
      { returnDocument: 'after' },
    );

    if (!result.value) {
      return res.status(404).json({ success: false, error: 'Товар не найден' });
    }

    res.json({ success: true, product: enrichProductData(result.value) });
  } catch (error) {
    console.error('Error updating product:', error);
    res.status(500).json({ success: false, error: 'Ошибка при обновлении товара' });
  }
});

app.delete('/api/admin/products/:id', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { db } = await connectToDatabase();
    const collection = db.collection(COLLECTION_NAME);

    const filter = /^[a-fA-F0-9]{24}$/.test(id) ? { _id: new ObjectId(id) } : { url: id };
    const result = await collection.deleteOne(filter);

    if (result.deletedCount === 0) {
      return res.status(404).json({ success: false, error: 'Товар не найден' });
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting product:', error);
    res.status(500).json({ success: false, error: 'Ошибка при удалении товара' });
  }
});

// Получить 15 случайных товаров (карточки)
app.get('/api/products/random', async (req, res) => {
  try {
    const { db } = await connectToDatabase();
    const collection = db.collection(COLLECTION_NAME);

    const randomProducts = await collection.aggregate([
      { $sample: { size: 15 } },
      {
        $project: {
          _id: 1,
          short_title: 1,
          description: 1,
          small_image: 1,
          categoryId: 1,
          categoryPath: 1,
          categoryFullSlug: 1,
          url: 1
        }
      }
    ]).toArray();

    const enrichedProducts = randomProducts.map(enrichProductData);

    res.json({
      success: true,
      count: enrichedProducts.length,
      products: enrichedProducts
    });

  } catch (error) {
    console.error('Error fetching random products:', error);
    res.status(500).json({
      success: false,
      error: 'Ошибка при получении товаров'
    });
  }
});

// Получить товары по пути категории (произвольная глубина)
app.get('/api/products/category/*', async (req, res) => {
  try {
    const { db } = await connectToDatabase();
    const collection = db.collection(COLLECTION_NAME);
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 15;
    const skip = (page - 1) * limit;

    const fullSlug = (req.params[0] || '').replace(/^\/+|\/+$/g, '');
    if (!fullSlug) {
      return res.status(400).json({ success: false, error: 'Не указан путь категории' });
    }

    const filter = { categoryFullSlug: fullSlug };

    const products = await collection.find(filter)
    .skip(skip)
    .limit(limit)
    .project({
      _id: 1,
      short_title: 1,
      description: 1,
      small_image: 1,
        categoryId: 1,
        categoryPath: 1,
        categoryFullSlug: 1,
      url: 1
    })
    .toArray();

    const enrichedProducts = products.map(enrichProductData);

    const total = await collection.countDocuments(filter);

    res.json({
      success: true,
      count: enrichedProducts.length,
      total,
      page,
      totalPages: Math.ceil(total / limit),
      products: enrichedProducts
    });

  } catch (error) {
    console.error('Error fetching products by category:', error);
    res.status(500).json({
      success: false,
      error: 'Ошибка при получении товаров'
    });
  }
});

// Публичное дерево категорий
app.get('/api/categories/tree', async (req, res) => {
  try {
    const { db } = await connectToDatabase();
    const categories = await db
      .collection(CATEGORIES_COLLECTION)
      .find({})
      .sort({ order: 1, name: 1 })
      .toArray();

    const tree = buildCategoriesTree(categories);
    res.json({ success: true, tree });
  } catch (error) {
    console.error('Error fetching category tree:', error);
    res.status(500).json({
      success: false,
      error: 'Ошибка при получении категорий'
    });
  }
});

// Совместимость: /api/categories => дерево
app.get('/api/categories', async (req, res) => {
  try {
    const { db } = await connectToDatabase();
    const categories = await db
      .collection(CATEGORIES_COLLECTION)
      .find({})
      .sort({ order: 1, name: 1 })
      .toArray();

    const tree = buildCategoriesTree(categories);
    res.json({ success: true, tree });
  } catch (error) {
    console.error('Error fetching categories:', error);
    res.status(500).json({
      success: false,
      error: 'Ошибка при получении категорий'
    });
  }
});

// Поиск товаров
app.get('/api/products/search', async (req, res) => {
  try {
    const { db } = await connectToDatabase();
    const collection = db.collection(COLLECTION_NAME);
    const query = req.query.q;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 15;
    const skip = (page - 1) * limit;

    if (!query) {
      return res.status(400).json({
        success: false,
        error: 'Параметр поиска отсутствует'
      });
    }

    const searchRegex = new RegExp(query, 'i');
    
    const filter = {
      $or: [
        { short_title: searchRegex },
        { full_title: searchRegex },
        { description: searchRegex },
        { tags: searchRegex },
        { url: searchRegex },
        { categoryFullSlug: searchRegex },
        { 'categoryPath.name': searchRegex },
        { 'categoryPath.slug': searchRegex }
      ]
    };

    const products = await collection.find(filter)
    .skip(skip)
    .limit(limit)
    .project({
      _id: 1,
      short_title: 1,
      description: 1,
      small_image: 1,
      categoryId: 1,
      categoryPath: 1,
      categoryFullSlug: 1,
      url: 1
    })
    .toArray();

    const enrichedProducts = products.map(enrichProductData);

    const total = await collection.countDocuments(filter);

    res.json({
      success: true,
      count: enrichedProducts.length,
      total,
      page,
      totalPages: Math.ceil(total / limit),
      products: enrichedProducts
    });

  } catch (error) {
    console.error('Error searching products:', error);
    res.status(500).json({
      success: false,
      error: 'Ошибка при поиске товаров'
    });
  }
});

// Получить товар по полному URL (с категориями)
app.get('/api/products/by-url/*', async (req, res) => {
  try {
    const { db } = await connectToDatabase();
    const collection = db.collection(COLLECTION_NAME);
    
    // Получаем полный путь после /by-url/
    const fullPath = (req.params[0] || '').replace(/^\/+|\/+$/g, '');
    const pathParts = fullPath.split('/').filter(Boolean);
    if (pathParts.length === 0) {
      return res.status(400).json({ success: false, error: 'Неверный путь' });
    }

    const productSlug = pathParts[pathParts.length - 1];
    const categoryFullSlug = pathParts.slice(0, -1).join('/');

    const product = await collection.findOne(
      categoryFullSlug
        ? { url: productSlug, categoryFullSlug }
        : { url: productSlug }
    );

    if (!product) {
      return res.status(404).json({
        success: false,
        error: 'Товар не найден'
      });
    }

    const enrichedProduct = enrichProductData(product);

    res.json({
      success: true,
      product: enrichedProduct
    });

  } catch (error) {
    console.error('Error fetching product by URL:', error);
    res.status(500).json({
      success: false,
      error: 'Ошибка при получении товара'
    });
  }
});

// Получить товар по ID или slug (fallback)
app.get('/api/products/:id', async (req, res) => {
  try {
    const { db } = await connectToDatabase();
    const collection = db.collection(COLLECTION_NAME);

    const id = req.params.id;
    let product = null;

    // Если это валидный ObjectId в hex-формате — пробуем по _id
    const isHexObjectId = /^[a-fA-F0-9]{24}$/.test(id);
    if (isHexObjectId) {
      try {
        product = await collection.findOne({ _id: new ObjectId(id) });
      } catch {
        product = null;
      }
    }

    // Если не нашли или id не ObjectId — ищем по url/названию/тегам
    if (!product) {
      product = await collection.findOne({
        $or: [
          { url: { $regex: id, $options: 'i' } },
          { short_title: { $regex: id, $options: 'i' } },
          { full_title: { $regex: id, $options: 'i' } },
          { tags: { $regex: id, $options: 'i' } },
        ],
      });
    }

    if (!product) {
      return res.status(404).json({
        success: false,
        error: 'Товар не найден'
      });
    }

    const enrichedProduct = enrichProductData(product);

    res.json({
      success: true,
      product: enrichedProduct
    });

  } catch (error) {
    console.error('Error fetching product:', error);
    res.status(500).json({
      success: false,
      error: 'Ошибка при получении товара'
    });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Для локальной разработки
if (process.env.NODE_ENV !== 'production') {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

// Export для Vercel
module.exports = app;