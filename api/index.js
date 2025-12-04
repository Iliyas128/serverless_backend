const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const cors = require('cors');

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

// Константа для названия коллекции
const COLLECTION_NAME = 'Data';

// Функция для генерации полного URL товара
function generateProductFullUrl(product) {
  if (!product.categories || product.categories.length === 0) {
    return `/catalog/${product.url.replace('catalog/', '')}`;
  }

  const slugs = product.categories
    .filter(cat => cat.slug)
    .map(cat => cat.slug)
    .join('/');

  const productSlug = product.url.replace('catalog/', '');
  
  return `/catalog/${slugs}/${productSlug}`;
}

// Функция для обогащения данных товара
function enrichProductData(product) {
  return {
    ...product,
    fullUrl: generateProductFullUrl(product)
  };
}

// API Routes

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
          categories: 1,
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

// Получить товар по ID (для детальной страницы)
app.get('/api/products/:id', async (req, res) => {
  try {
    const { db } = await connectToDatabase();
    const collection = db.collection(COLLECTION_NAME);
    
    const product = await collection.findOne({
      _id: new ObjectId(req.params.id)
    });

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

// Получить товары по slug категории
app.get('/api/products/category/:categorySlug', async (req, res) => {
  try {
    const { db } = await connectToDatabase();
    const collection = db.collection(COLLECTION_NAME);
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 15;
    const skip = (page - 1) * limit;

    const categorySlug = req.params.categorySlug;

    const products = await collection.find({
      'categories.slug': categorySlug
    })
    .skip(skip)
    .limit(limit)
    .project({
      _id: 1,
      short_title: 1,
      description: 1,
      small_image: 1,
      categories: 1,
      url: 1
    })
    .toArray();

    const enrichedProducts = products.map(enrichProductData);

    const total = await collection.countDocuments({
      'categories.slug': categorySlug
    });

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

// Получить все категории с их slug'ами
app.get('/api/categories', async (req, res) => {
  try {
    const { db } = await connectToDatabase();
    const collection = db.collection(COLLECTION_NAME);

    // Получаем все уникальные категории
    const categoriesData = await collection.aggregate([
      { $unwind: '$categories' },
      { 
        $group: { 
          _id: '$categories.slug',
          name: { $first: '$categories.name' },
          slug: { $first: '$categories.slug' }
        } 
      },
      { $sort: { name: 1 } }
    ]).toArray();

    // Основные 6 категорий
    const mainCategories = [
      'Медицинское оборудование',
      'Металлопрокат',
      'Промышленное оборудование',
      'Химические реактивы для заводов и промышленности',
      'Трубопроводная и запорная арматура',
      'Сварочное оборудование'
    ];

    // Группируем категории по основным направлениям
    const groupedCategories = {};
    
    for (const mainCat of mainCategories) {
      const subcategories = await collection.aggregate([
        { $match: { 'categories.name': mainCat } },
        { $unwind: '$categories' },
        { $match: { 'categories.name': { $ne: mainCat } } },
        { 
          $group: { 
            _id: '$categories.slug',
            name: { $first: '$categories.name' },
            slug: { $first: '$categories.slug' }
          } 
        },
        { $sort: { name: 1 } }
      ]).toArray();

      const mainCatData = categoriesData.find(c => c.name === mainCat);
      
      groupedCategories[mainCat] = {
        name: mainCat,
        slug: mainCatData?.slug || null,
        subcategories: subcategories.map(sub => ({
          name: sub.name,
          slug: sub.slug
        }))
      };
    }

    res.json({
      success: true,
      mainCategories: groupedCategories,
      allCategories: categoriesData.map(cat => ({
        name: cat.name,
        slug: cat.slug
      }))
    });

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
    
    const products = await collection.find({
      $or: [
        { short_title: searchRegex },
        { full_title: searchRegex },
        { description: searchRegex },
        { tags: searchRegex }
      ]
    })
    .skip(skip)
    .limit(limit)
    .project({
      _id: 1,
      short_title: 1,
      description: 1,
      small_image: 1,
      categories: 1,
      url: 1
    })
    .toArray();

    const enrichedProducts = products.map(enrichProductData);

    const total = await collection.countDocuments({
      $or: [
        { short_title: searchRegex },
        { full_title: searchRegex },
        { description: searchRegex },
        { tags: searchRegex }
      ]
    });

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
    const fullPath = req.params[0];
    const pathParts = fullPath.split('/');
    const productSlug = pathParts[pathParts.length - 1];

    const product = await collection.findOne({
      url: { $regex: productSlug, $options: 'i' }
    });

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