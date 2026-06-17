const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Supabase Config (HARDCODED FOR TESTING) ──────────────────────────────────
const SUPABASE_URL = 'https://hkbohyjkufmdfvawdwlg.supabase.co';
const SUPABASE_SERVICE_KEY = 'sb_secret_4sj9iSh8jE8i4GLpZBc0tw__JkriFvQ';
const SUPABASE_ANON_KEY = 'sb_publishable_rRZZZaYICMtOWEb8CvPyfw_vLydT_HX';
const ADMIN_WHATSAPP = '+27634530070'; // Replace with admin WhatsApp

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

// ─── Middleware ────────────────────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-user-id', 'x-admin-key']
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 500 });
app.use(limiter);

// ─── Error Helper ──────────────────────────────────────────────────────────────
function sendError(res, status, message, detail = null) {
  const payload = { success: false, error: message };
  if (detail) payload.detail = detail;
  return res.status(status).json(payload);
}
function sendSuccess(res, data, message = 'Success') {
  return res.json({ success: true, message, data });
}

// ─── Auth Middleware ───────────────────────────────────────────────────────────
async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return sendError(res, 401, 'Authorization header missing');
  const token = authHeader.replace('Bearer ', '');
  const { data: { user }, error } = await supabase.auth.getUser(token);
  if (error || !user) return sendError(res, 401, 'Invalid or expired session. Please log in again.');
  req.user = user;
  next();
}

async function requireAdmin(req, res, next) {
  const adminKey = req.headers['x-admin-key'];
  if (!adminKey) return sendError(res, 401, 'Admin key required');
  const { data, error } = await supabase.from('admin_keys').select('*').eq('key', adminKey).eq('active', true).single();
  if (error || !data) return sendError(res, 401, 'Invalid admin credentials');
  req.admin = data;
  next();
}

// ─── HEALTH ───────────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => sendSuccess(res, { status: 'online', time: new Date() }, 'Server is running'));

// ═════════════════════════════════════════════════════════════════════════════
// AUTH ROUTES
// ═════════════════════════════════════════════════════════════════════════════

// Register with email/password
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, full_name, country, phone } = req.body;
    if (!email || !password || !full_name || !country) {
      return sendError(res, 400, 'Email, password, full name and country are required');
    }
    const { data: authData, error: authError } = await supabase.auth.signUp({ email, password });
    if (authError) return sendError(res, 400, authError.message);

    const userId = authData.user?.id;
    if (!userId) return sendError(res, 500, 'Account creation failed. Please try again.');

    const { error: profileError } = await supabase.from('profiles').insert({
      id: userId, email, full_name, country, phone: phone || null, role: 'buyer',
      created_at: new Date().toISOString()
    });
    if (profileError) return sendError(res, 500, 'Account created but profile save failed: ' + profileError.message);

    // Send welcome notification
    await supabase.from('notifications').insert({
      user_id: userId, type: 'welcome', title: 'Welcome to Zmafrdeal!',
      message: `Hi ${full_name}, welcome to Zmafrdeal! Start shopping the best deals from Sierra Leone and beyond.`,
      read: false, created_at: new Date().toISOString()
    });

    return sendSuccess(res, { user: authData.user }, 'Account created successfully');
  } catch (e) {
    return sendError(res, 500, 'Unexpected server error: ' + e.message);
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return sendError(res, 400, 'Email and password are required');
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) return sendError(res, 401, error.message);
    const { data: profile } = await supabase.from('profiles').select('*').eq('id', data.user.id).single();
    return sendSuccess(res, { user: data.user, session: data.session, profile }, 'Login successful');
  } catch (e) {
    return sendError(res, 500, 'Login failed: ' + e.message);
  }
});

// Forgot password
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return sendError(res, 400, 'Email is required');
    const { error } = await supabase.auth.resetPasswordForEmail(email);
    if (error) return sendError(res, 400, error.message);
    return sendSuccess(res, null, 'Password reset email sent. Check your inbox.');
  } catch (e) {
    return sendError(res, 500, 'Password reset failed: ' + e.message);
  }
});

// Get profile
app.get('/api/auth/profile', requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('profiles').select('*').eq('id', req.user.id).single();
    if (error) return sendError(res, 404, 'Profile not found');
    return sendSuccess(res, data);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

// Update profile
app.put('/api/auth/profile', requireAuth, async (req, res) => {
  try {
    const { full_name, phone, country, avatar_url, settings } = req.body;
    const updates = {};
    if (full_name) updates.full_name = full_name;
    if (phone) updates.phone = phone;
    if (country) updates.country = country;
    if (avatar_url) updates.avatar_url = avatar_url;
    if (settings) updates.settings = settings;
    updates.updated_at = new Date().toISOString();

    const { data, error } = await supabase.from('profiles').update(updates).eq('id', req.user.id).select().single();
    if (error) return sendError(res, 500, 'Profile update failed: ' + error.message);
    return sendSuccess(res, data, 'Profile updated successfully');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// SELLER ROUTES
// ═════════════════════════════════════════════════════════════════════════════

app.post('/api/sellers/apply', async (req, res) => {
  try {
    const { full_name, email, password, business_name, business_type, phone, country, id_number, address, description } = req.body;
    if (!email || !password || !full_name || !business_name || !phone) {
      return sendError(res, 400, 'Full name, email, password, business name and phone are required');
    }
    const { data: authData, error: authError } = await supabase.auth.signUp({ email, password });
    if (authError) return sendError(res, 400, authError.message);

    const userId = authData.user?.id;
    await supabase.from('profiles').insert({
      id: userId, email, full_name, country: country || 'Sierra Leone', phone, role: 'seller_pending',
      created_at: new Date().toISOString()
    });

    const { error: sellerError } = await supabase.from('sellers').insert({
      id: userId, business_name, business_type, phone, country: country || 'Sierra Leone',
      id_number, address, description, status: 'pending', commission_rate: 10,
      created_at: new Date().toISOString()
    });
    if (sellerError) return sendError(res, 500, 'Seller application failed: ' + sellerError.message);
    return sendSuccess(res, null, 'Seller application submitted. Await admin approval.');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.post('/api/sellers/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) return sendError(res, 401, error.message);
    const { data: profile } = await supabase.from('profiles').select('*').eq('id', data.user.id).single();
    if (!profile || !['seller', 'seller_pending'].includes(profile.role)) {
      return sendError(res, 403, 'This account is not registered as a seller');
    }
    const { data: seller } = await supabase.from('sellers').select('*').eq('id', data.user.id).single();
    return sendSuccess(res, { user: data.user, session: data.session, profile, seller });
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.get('/api/sellers/dashboard', requireAuth, async (req, res) => {
  try {
    const { data: seller } = await supabase.from('sellers').select('*').eq('id', req.user.id).single();
    if (!seller) return sendError(res, 403, 'Not a registered seller');
    const { data: products } = await supabase.from('products').select('*').eq('seller_id', req.user.id);
    const { data: orders } = await supabase.from('orders').select('*').eq('seller_id', req.user.id);
    const totalRevenue = orders?.filter(o => o.status === 'completed').reduce((s, o) => s + (o.total || 0), 0) || 0;
    return sendSuccess(res, { seller, products: products || [], orders: orders || [], total_revenue: totalRevenue });
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// PRODUCTS ROUTES
// ═════════════════════════════════════════════════════════════════════════════

// Get all products (public - country filtered)
app.get('/api/products', async (req, res) => {
  try {
    const { country, category, search, limit = 50, offset = 0, sort = 'created_at', flash_sale } = req.query;

    let query = supabase.from('products').select('*, reviews(rating)').eq('status', 'active').eq('hidden', false);

    if (category) query = query.eq('category', category);
    if (flash_sale === 'true') query = query.eq('is_flash_sale', true);
    if (search) query = query.ilike('name', `%${search}%`);

    if (country && country !== 'all') {
      query = query.or(`target_countries.cs.{${country}},show_to_all.eq.true`);
    }

    if (sort === 'price_asc') query = query.order('price', { ascending: true });
    else if (sort === 'price_desc') query = query.order('price', { ascending: false });
    else if (sort === 'popular') query = query.order('sales_count', { ascending: false });
    else query = query.order('created_at', { ascending: false });

    query = query.range(parseInt(offset), parseInt(offset) + parseInt(limit) - 1);

    const { data, error } = await query;
    if (error) return sendError(res, 500, 'Failed to load products: ' + error.message);

    const productsWithRatings = (data || []).map(p => {
      const reviews = p.reviews || [];
      const avg = reviews.length ? reviews.reduce((s, r) => s + r.rating, 0) / reviews.length : 0;
      return { ...p, avg_rating: parseFloat(avg.toFixed(1)), review_count: reviews.length, reviews: undefined };
    });

    return sendSuccess(res, productsWithRatings);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

// Get single product
app.get('/api/products/:id', async (req, res) => {
  try {
    const { data, error } = await supabase.from('products').select('*').eq('id', req.params.id).single();
    if (error || !data) return sendError(res, 404, 'Product not found');
    const { data: reviews } = await supabase.from('reviews').select('*').eq('product_id', req.params.id).eq('approved', true).order('created_at', { ascending: false });
    const avg = reviews?.length ? reviews.reduce((s, r) => s + r.rating, 0) / reviews.length : 0;
    return sendSuccess(res, { ...data, reviews: reviews || [], avg_rating: parseFloat(avg.toFixed(1)), review_count: reviews?.length || 0 });
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

// Get flash sale products
app.get('/api/products/flash-sale/active', async (req, res) => {
  try {
    const now = new Date().toISOString();
    const { data, error } = await supabase.from('products').select('*').eq('is_flash_sale', true).eq('status', 'active').gt('flash_sale_end', now);
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data || []);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

// Get best sellers
app.get('/api/products/best-sellers/list', async (req, res) => {
  try {
    const { data, error } = await supabase.from('products').select('*').eq('status', 'active').order('sales_count', { ascending: false }).limit(20);
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data || []);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

// Get most purchased
app.get('/api/products/most-purchased/list', async (req, res) => {
  try {
    const { data, error } = await supabase.from('products').select('*').eq('status', 'active').order('sales_count', { ascending: false }).limit(20);
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data || []);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

// Post product (seller or admin)
app.post('/api/products', requireAuth, async (req, res) => {
  try {
    const product = {
      ...req.body,
      id: uuidv4(),
      seller_id: req.user.id,
      status: 'pending_approval',
      sales_count: 0,
      created_at: new Date().toISOString()
    };

    const { data: profile } = await supabase.from('profiles').select('role').eq('id', req.user.id).single();
    if (profile?.role === 'admin') product.status = 'active';

    const { data, error } = await supabase.from('products').insert(product).select().single();
    if (error) return sendError(res, 500, 'Product posting failed: ' + error.message);
    return sendSuccess(res, data, 'Product posted successfully');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

// Update product
app.put('/api/products/:id', requireAuth, async (req, res) => {
  try {
    const updates = { ...req.body, updated_at: new Date().toISOString() };
    delete updates.id; delete updates.seller_id; delete updates.created_at;
    const { data, error } = await supabase.from('products').update(updates).eq('id', req.params.id).select().single();
    if (error) return sendError(res, 500, 'Product update failed: ' + error.message);
    return sendSuccess(res, data, 'Product updated');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// CATEGORIES
// ═════════════════════════════════════════════════════════════════════════════

app.get('/api/categories', async (req, res) => {
  try {
    const { data, error } = await supabase.from('categories').select('*').eq('active', true).order('sort_order');
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data || []);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.post('/api/categories', requireAuth, async (req, res) => {
  try {
    const { name, icon, sort_order } = req.body;
    if (!name) return sendError(res, 400, 'Category name is required');
    const { data, error } = await supabase.from('categories').insert({ name, icon, sort_order: sort_order || 0, active: true }).select().single();
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data, 'Category created');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.delete('/api/categories/:id', requireAuth, async (req, res) => {
  try {
    const { error } = await supabase.from('categories').delete().eq('id', req.params.id);
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, null, 'Category deleted');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// CART ROUTES
// ═════════════════════════════════════════════════════════════════════════════

app.get('/api/cart', requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('cart_items').select('*, products(*)').eq('user_id', req.user.id);
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data || []);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.post('/api/cart', requireAuth, async (req, res) => {
  try {
    const { product_id, quantity, variation } = req.body;
    if (!product_id) return sendError(res, 400, 'Product ID is required');

    const { data: existing } = await supabase.from('cart_items').select('*').eq('user_id', req.user.id).eq('product_id', product_id).single();
    if (existing) {
      const { data, error } = await supabase.from('cart_items').update({ quantity: existing.quantity + (quantity || 1), variation }).eq('id', existing.id).select().single();
      if (error) return sendError(res, 500, error.message);
      return sendSuccess(res, data, 'Cart updated');
    }

    const { data, error } = await supabase.from('cart_items').insert({ user_id: req.user.id, product_id, quantity: quantity || 1, variation, created_at: new Date().toISOString() }).select().single();
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data, 'Added to cart');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.delete('/api/cart/:id', requireAuth, async (req, res) => {
  try {
    const { error } = await supabase.from('cart_items').delete().eq('id', req.params.id).eq('user_id', req.user.id);
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, null, 'Item removed from cart');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// WISHLIST
// ═════════════════════════════════════════════════════════════════════════════

app.get('/api/wishlist', requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('wishlist').select('*, products(*)').eq('user_id', req.user.id);
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data || []);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.post('/api/wishlist', requireAuth, async (req, res) => {
  try {
    const { product_id } = req.body;
    if (!product_id) return sendError(res, 400, 'Product ID is required');
    const { data: existing } = await supabase.from('wishlist').select('*').eq('user_id', req.user.id).eq('product_id', product_id).single();
    if (existing) {
      await supabase.from('wishlist').delete().eq('id', existing.id);
      return sendSuccess(res, { removed: true }, 'Removed from wishlist');
    }
    const { data, error } = await supabase.from('wishlist').insert({ user_id: req.user.id, product_id, created_at: new Date().toISOString() }).select().single();
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data, 'Added to wishlist');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// ORDERS
// ═════════════════════════════════════════════════════════════════════════════

app.post('/api/orders', requireAuth, async (req, res) => {
  try {
    const { items, delivery_info, payment_method, subtotal, discount, shipping_fee, total, voucher_code } = req.body;
    if (!items || !items.length) return sendError(res, 400, 'Order items are required');
    if (!delivery_info?.full_name || !delivery_info?.phone) return sendError(res, 400, 'Delivery information is required');

    const orderId = uuidv4().split('-')[0].toUpperCase();
    const { data: order, error } = await supabase.from('orders').insert({
      id: orderId, user_id: req.user.id, items: JSON.stringify(items),
      delivery_info: JSON.stringify(delivery_info), payment_method,
      subtotal, discount: discount || 0, shipping_fee: shipping_fee || 0, total,
      voucher_code: voucher_code || null, status: 'pending',
      created_at: new Date().toISOString()
    }).select().single();

    if (error) return sendError(res, 500, 'Order placement failed: ' + error.message);

    // Update product sales count
    for (const item of items) {
      await supabase.rpc('increment_sales', { product_id: item.product_id, amount: item.quantity });
    }

    // Notify user
    await supabase.from('notifications').insert({
      user_id: req.user.id, type: 'order_placed', title: 'Order Placed Successfully',
      message: `Your order #${orderId} has been placed and is pending confirmation.`,
      read: false, created_at: new Date().toISOString()
    });

    // Clear cart
    if (payment_method !== 'cart_manual') {
      await supabase.from('cart_items').delete().eq('user_id', req.user.id);
    }

    return sendSuccess(res, order, 'Order placed successfully');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.get('/api/orders', requireAuth, async (req, res) => {
  try {
    const { status } = req.query;
    let query = supabase.from('orders').select('*').eq('user_id', req.user.id).order('created_at', { ascending: false });
    if (status) query = query.eq('status', status);
    const { data, error } = await query;
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data || []);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.get('/api/orders/:id', requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('orders').select('*').eq('id', req.params.id).eq('user_id', req.user.id).single();
    if (error || !data) return sendError(res, 404, 'Order not found');
    return sendSuccess(res, data);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// REVIEWS
// ═════════════════════════════════════════════════════════════════════════════

app.post('/api/reviews', async (req, res) => {
  try {
    const { product_id, user_name, rating, comment, user_id } = req.body;
    if (!product_id || !user_name || !rating) return sendError(res, 400, 'Product, name and rating are required');
    if (rating < 1 || rating > 5) return sendError(res, 400, 'Rating must be between 1 and 5');

    const { data, error } = await supabase.from('reviews').insert({
      id: uuidv4(), product_id, user_id: user_id || null, user_name,
      rating: parseInt(rating), comment: comment || null, approved: false,
      created_at: new Date().toISOString()
    }).select().single();

    if (error) return sendError(res, 500, 'Review submission failed: ' + error.message);
    return sendSuccess(res, data, 'Review submitted. Pending admin approval.');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.get('/api/reviews/:product_id', async (req, res) => {
  try {
    const { data, error } = await supabase.from('reviews').select('*').eq('product_id', req.params.product_id).eq('approved', true).order('created_at', { ascending: false });
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data || []);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// VOUCHERS
// ═════════════════════════════════════════════════════════════════════════════

app.post('/api/vouchers/validate', async (req, res) => {
  try {
    const { code, product_id, user_id } = req.body;
    if (!code) return sendError(res, 400, 'Voucher code is required');

    const { data, error } = await supabase.from('vouchers').select('*').eq('code', code.toUpperCase()).eq('active', true).single();
    if (error || !data) return sendError(res, 404, 'Invalid voucher code');

    const now = new Date();
    if (data.expires_at && new Date(data.expires_at) < now) return sendError(res, 400, 'Voucher has expired');
    if (data.usage_count >= data.usage_limit) return sendError(res, 400, 'Voucher usage limit reached');

    return sendSuccess(res, { discount_type: data.discount_type, discount_value: data.discount_value, min_order: data.min_order }, 'Voucher is valid');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.get('/api/vouchers/user/:user_id', requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('user_vouchers').select('*, vouchers(*)').eq('user_id', req.user.id);
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data || []);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// NOTIFICATIONS
// ═════════════════════════════════════════════════════════════════════════════

app.get('/api/notifications', requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('notifications').select('*').eq('user_id', req.user.id).order('created_at', { ascending: false }).limit(50);
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data || []);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.patch('/api/notifications/:id/read', requireAuth, async (req, res) => {
  try {
    const { error } = await supabase.from('notifications').update({ read: true }).eq('id', req.params.id).eq('user_id', req.user.id);
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, null, 'Notification marked as read');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.patch('/api/notifications/read-all', requireAuth, async (req, res) => {
  try {
    await supabase.from('notifications').update({ read: true }).eq('user_id', req.user.id).eq('read', false);
    return sendSuccess(res, null, 'All notifications marked as read');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// BANNERS (Admin set)
// ═════════════════════════════════════════════════════════════════════════════

app.get('/api/banners', async (req, res) => {
  try {
    const { data, error } = await supabase.from('banners').select('*').eq('active', true).order('sort_order');
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data || []);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.post('/api/banners', requireAuth, async (req, res) => {
  try {
    const { title, image_url, link_url, sort_order } = req.body;
    if (!image_url) return sendError(res, 400, 'Banner image URL is required');
    const { data, error } = await supabase.from('banners').insert({ title, image_url, link_url, sort_order: sort_order || 0, active: true }).select().single();
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data, 'Banner created');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// ADMIN ROUTES
// ═════════════════════════════════════════════════════════════════════════════

app.get('/api/admin/products', requireAuth, async (req, res) => {
  try {
    const { status } = req.query;
    let query = supabase.from('products').select('*').order('created_at', { ascending: false });
    if (status) query = query.eq('status', status);
    const { data, error } = await query;
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data || []);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.patch('/api/admin/products/:id/status', requireAuth, async (req, res) => {
  try {
    const { status } = req.body;
    const { data, error } = await supabase.from('products').update({ status, updated_at: new Date().toISOString() }).eq('id', req.params.id).select().single();
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data, 'Product status updated');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.patch('/api/admin/products/:id/hide', requireAuth, async (req, res) => {
  try {
    const { hidden } = req.body;
    const { data, error } = await supabase.from('products').update({ hidden }).eq('id', req.params.id).select().single();
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data, `Product ${hidden ? 'hidden' : 'visible'}`);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.delete('/api/admin/products/:id', requireAuth, async (req, res) => {
  try {
    const { error } = await supabase.from('products').delete().eq('id', req.params.id);
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, null, 'Product deleted');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.get('/api/admin/orders', requireAuth, async (req, res) => {
  try {
    const { status } = req.query;
    let query = supabase.from('orders').select('*').order('created_at', { ascending: false });
    if (status) query = query.eq('status', status);
    const { data, error } = await query;
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data || []);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.patch('/api/admin/orders/:id/status', requireAuth, async (req, res) => {
  try {
    const { status } = req.body;
    const { data: order } = await supabase.from('orders').select('user_id').eq('id', req.params.id).single();
    const { data, error } = await supabase.from('orders').update({ status, updated_at: new Date().toISOString() }).eq('id', req.params.id).select().single();
    if (error) return sendError(res, 500, error.message);
    if (order?.user_id) {
      const msgs = { confirmed: 'Your order has been confirmed!', shipped: 'Your order is on its way!', completed: 'Your order has been delivered!', cancelled: 'Your order has been cancelled.' };
      await supabase.from('notifications').insert({ user_id: order.user_id, type: 'order_update', title: `Order ${status.charAt(0).toUpperCase() + status.slice(1)}`, message: msgs[status] || `Order status: ${status}`, read: false, created_at: new Date().toISOString() });
    }
    return sendSuccess(res, data, 'Order status updated');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.get('/api/admin/reviews', requireAuth, async (req, res) => {
  try {
    const { approved } = req.query;
    let query = supabase.from('reviews').select('*, products(name)').order('created_at', { ascending: false });
    if (approved !== undefined) query = query.eq('approved', approved === 'true');
    const { data, error } = await query;
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data || []);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.patch('/api/admin/reviews/:id', requireAuth, async (req, res) => {
  try {
    const { approved } = req.body;
    const { data, error } = await supabase.from('reviews').update({ approved }).eq('id', req.params.id).select().single();
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data, `Review ${approved ? 'approved' : 'rejected'}`);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.delete('/api/admin/reviews/:id', requireAuth, async (req, res) => {
  try {
    const { error } = await supabase.from('reviews').delete().eq('id', req.params.id);
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, null, 'Review deleted');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.get('/api/admin/sellers', requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('sellers').select('*, profiles(full_name, email)').order('created_at', { ascending: false });
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data || []);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.patch('/api/admin/sellers/:id/status', requireAuth, async (req, res) => {
  try {
    const { status } = req.body;
    await supabase.from('sellers').update({ status }).eq('id', req.params.id);
    const role = status === 'approved' ? 'seller' : 'buyer';
    await supabase.from('profiles').update({ role }).eq('id', req.params.id);
    if (status === 'approved') {
      await supabase.from('notifications').insert({ user_id: req.params.id, type: 'seller_approved', title: 'Seller Application Approved', message: 'Congratulations! Your seller application has been approved. You can now post products on Zmafrdeal.', read: false, created_at: new Date().toISOString() });
    }
    return sendSuccess(res, null, `Seller ${status}`);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.get('/api/admin/analytics', requireAuth, async (req, res) => {
  try {
    const [products, orders, users, reviews] = await Promise.all([
      supabase.from('products').select('id, status, sales_count, price'),
      supabase.from('orders').select('id, status, total, created_at'),
      supabase.from('profiles').select('id, country, created_at'),
      supabase.from('reviews').select('id, approved')
    ]);
    const totalRevenue = (orders.data || []).filter(o => o.status === 'completed').reduce((s, o) => s + (o.total || 0), 0);
    const pendingOrders = (orders.data || []).filter(o => o.status === 'pending').length;
    return sendSuccess(res, {
      total_products: products.data?.length || 0,
      active_products: products.data?.filter(p => p.status === 'active').length || 0,
      total_orders: orders.data?.length || 0, pending_orders: pendingOrders,
      total_revenue: totalRevenue, total_users: users.data?.length || 0,
      pending_reviews: reviews.data?.filter(r => !r.approved).length || 0
    });
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

// Voucher management
app.post('/api/admin/vouchers', requireAuth, async (req, res) => {
  try {
    const { code, discount_type, discount_value, min_order, usage_limit, expires_at } = req.body;
    if (!code || !discount_type || !discount_value) return sendError(res, 400, 'Code, type and value are required');
    const { data, error } = await supabase.from('vouchers').insert({ code: code.toUpperCase(), discount_type, discount_value, min_order: min_order || 0, usage_limit: usage_limit || 100, usage_count: 0, expires_at, active: true, created_at: new Date().toISOString() }).select().single();
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data, 'Voucher created');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.get('/api/admin/vouchers', requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('vouchers').select('*').order('created_at', { ascending: false });
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data || []);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

// Send notification to user
app.post('/api/admin/notifications/send', requireAuth, async (req, res) => {
  try {
    const { user_id, type, title, message } = req.body;
    if (!user_id || !title || !message) return sendError(res, 400, 'User ID, title and message required');
    const { data, error } = await supabase.from('notifications').insert({ user_id, type: type || 'admin_message', title, message, read: false, created_at: new Date().toISOString() }).select().single();
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data, 'Notification sent');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

// Public settings endpoint (no auth required — used by buyer + seller pages)
app.get('/api/settings', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('site_settings')
      .select('default_currency, currency_symbol, currency_name, default_country, store_name, tagline, whatsapp_number, show_banners, show_flash_sale, maintenance_mode, pwa_enabled')
      .eq('id', 1)
      .single();
    if (error) {
      // Return defaults if no settings exist yet
      return sendSuccess(res, { default_currency: 'SLL', currency_symbol: 'Le', currency_name: 'Sierra Leonean Leone', default_country: 'Sierra Leone', store_name: 'Zmafrdeal' });
    }
    return sendSuccess(res, data);
  } catch (e) {
    return sendSuccess(res, { default_currency: 'SLL', currency_symbol: 'Le', currency_name: 'Sierra Leonean Leone', default_country: 'Sierra Leone', store_name: 'Zmafrdeal' });
  }
});

// Admin settings
app.get('/api/admin/settings', async (req, res) => {
  try {
    const { data, error } = await supabase.from('site_settings').select('*').single();
    if (error) return sendError(res, 404, 'Settings not found');
    return sendSuccess(res, data);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.put('/api/admin/settings', requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('site_settings').upsert({ id: 1, ...req.body, updated_at: new Date().toISOString() }).select().single();
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data, 'Settings saved');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

// Messages (user to admin)
app.post('/api/messages', requireAuth, async (req, res) => {
  try {
    const { subject, message } = req.body;
    if (!message) return sendError(res, 400, 'Message is required');
    const { data, error } = await supabase.from('messages').insert({ user_id: req.user.id, subject: subject || 'General Inquiry', message, status: 'unread', created_at: new Date().toISOString() }).select().single();
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data, 'Message sent to admin');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.get('/api/admin/messages', requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('messages').select('*, profiles(full_name, email)').order('created_at', { ascending: false });
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data || []);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

// Search history (recently viewed)
app.post('/api/recently-viewed', async (req, res) => {
  try {
    const { user_id, product_id } = req.body;
    if (!product_id) return sendError(res, 400, 'Product ID required');
    if (user_id) {
      await supabase.from('recently_viewed').upsert({ user_id, product_id, viewed_at: new Date().toISOString() });
    }
    return sendSuccess(res, null, 'Recorded');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.get('/api/recently-viewed/:user_id', requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('recently_viewed').select('*, products(*)').eq('user_id', req.params.user_id).order('viewed_at', { ascending: false }).limit(20);
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data || []);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

// 404 handler
app.use((req, res) => sendError(res, 404, `Route ${req.method} ${req.path} not found`));

// Global error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  sendError(res, 500, 'Internal server error: ' + err.message);
});

app.listen(PORT, () => {
  console.log(`Zmafrdeal server running on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/api/health`);
});

module.exports = app;
