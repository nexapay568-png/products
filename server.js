const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Supabase Config ───────────────────────────────────────────────────────────
const SUPABASE_URL = 'https://izppgooonnhmlmysykwx.supabase.co';
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const SUPABASE_ANON_KEY = 'sb_publishable_X1e17sw4k_sl5eb4XKI1fw_T8c_0F4Z';
const ADMIN_WHATSAPP = '+27634530070';

if (!SUPABASE_SERVICE_KEY) {
  console.error('⚠️  WARNING: SUPABASE_SERVICE_KEY environment variable is not set!');
  console.error('   All server-side database writes (sellers, messages, notifications, orders)');
  console.error('   will fail with Row Level Security errors.');
  console.error('   → Set SUPABASE_SERVICE_KEY in your Render environment variables.');
}

// Always use service key (bypasses RLS). Never fall back to anon key for server operations.
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false }
});

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

// ─── Admin key helper ─────────────────────────────────────────────────────────
// Fallback key for when the DB is unreachable (e.g. SUPABASE_SERVICE_KEY not set).
// Matches the key hardcoded in admin.html so the admin panel always works.
const HARDCODED_ADMIN_KEY = process.env.ADMIN_KEY || 'ZMAFRDEAL-ADMIN-2024';

async function lookupAdminKey(key) {
  // 1. Try DB lookup (bypasses RLS via service key)
  try {
    const { data, error } = await supabase
      .from('admin_keys')
      .select('*')
      .eq('key', key)
      .eq('active', true)
      .single();
    if (!error && data) return { id: data.user_id || 'admin', role: 'admin', record: data };
  } catch (_) { /* DB unreachable — fall through to hardcoded check */ }

  // 2. Hardcoded fallback — works even when SUPABASE_SERVICE_KEY is not set
  if (key === HARDCODED_ADMIN_KEY) {
    return { id: 'admin', role: 'admin', record: { key, name: 'Default Admin' } };
  }

  return null;
}

// ─── Auth Middleware ───────────────────────────────────────────────────────────
async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return sendError(res, 401, 'Authorization header missing');
  const token = authHeader.replace('Bearer ', '');
  try {
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) return sendError(res, 401, 'Invalid or expired session. Please log in again.');
    req.user = user;
    next();
  } catch (e) {
    return sendError(res, 401, 'Invalid or expired session. Please log in again.');
  }
}

async function requireAdmin(req, res, next) {
  const adminKey = req.headers['x-admin-key'];
  if (!adminKey) return sendError(res, 401, 'Admin key required');
  const admin = await lookupAdminKey(adminKey);
  if (!admin) return sendError(res, 401, 'Invalid admin credentials');
  req.admin = admin.record;
  req.user = { id: admin.id, role: 'admin' };
  next();
}

// Accepts either a valid admin key OR a valid user JWT.
// IMPORTANT: if x-admin-key is present it is checked first and exclusively —
// we do NOT fall through to JWT auth when a key is supplied but wrong.
async function requireAuthOrAdmin(req, res, next) {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey) {
    const admin = await lookupAdminKey(adminKey);
    if (!admin) return sendError(res, 401, 'Invalid admin credentials');
    req.admin = admin.record;
    req.user = { id: admin.id, role: 'admin' };
    return next();
  }
  // No admin key — try user JWT
  const authHeader = req.headers.authorization;
  if (!authHeader) return sendError(res, 401, 'Authorization required');
  const token = authHeader.replace('Bearer ', '');
  try {
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) return sendError(res, 401, 'Invalid or expired session. Please log in again.');
    req.user = user;
    next();
  } catch (e) {
    return sendError(res, 401, 'Invalid or expired session. Please log in again.');
  }
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

    // Use admin.createUser with email_confirm:true so the account is instantly
    // confirmed regardless of whether Supabase email confirmation is enabled.
    // This guarantees signInWithPassword succeeds immediately after.
    const { data: adminData, error: adminError } = await supabase.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: { full_name }
    });

    // Fall back to regular signUp if admin API is unavailable (e.g. missing service key)
    let userId, authUser;
    if (adminError) {
      const { data: signUpData, error: signUpError } = await supabase.auth.signUp({ email, password });
      if (signUpError) return sendError(res, 400, signUpError.message);
      userId = signUpData.user?.id;
      authUser = signUpData.user;
    } else {
      userId = adminData.user?.id;
      authUser = adminData.user;
    }

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

    // Sign in to get a live session — works now because account is already confirmed
    const { data: signInData } = await supabase.auth.signInWithPassword({ email, password });
    const session = signInData?.session || null;
    const profile = { id: userId, email, full_name, country, phone: phone || null, role: 'buyer' };

    return sendSuccess(res, { user: authUser, session, profile }, 'Account created successfully');
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
    if (phone !== undefined) updates.phone = phone || null;
    if (country !== undefined) updates.country = country || null;
    if (avatar_url !== undefined) updates.avatar_url = avatar_url || null;
    if (settings !== undefined) updates.settings = settings;
    updates.updated_at = new Date().toISOString();

    let { data, error } = await supabase.from('profiles').update(updates).eq('id', req.user.id).select().single();

    // If the error is about the settings column not existing, retry without it
    if (error && error.message && error.message.includes('settings')) {
      const { settings: _dropped, ...fallbackUpdates } = updates;
      const fallback = await supabase.from('profiles').update(fallbackUpdates).eq('id', req.user.id).select().single();
      data = fallback.data;
      error = fallback.error;
    }

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
    if (profile.banned) {
      return res.status(403).json({
        success: false,
        banned: true,
        ban_reason: profile.ban_reason || null,
        error: 'Your seller account has been suspended.'
      });
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
    const { country, category, search, limit = 50, offset = 0, sort = 'popular', flash_sale,
      min_price, max_price, min_rating, on_sale, in_stock, free_shipping } = req.query;

    let query = supabase.from('products').select('*, reviews(rating)').eq('status', 'active').or('hidden.eq.false,hidden.is.null');

    if (category) query = query.eq('category', category);
    if (flash_sale === 'true') query = query.eq('is_flash_sale', true);
    if (search) query = query.ilike('name', `%${search}%`);
    if (min_price) query = query.gte('price', parseFloat(min_price));
    if (max_price) query = query.lte('price', parseFloat(max_price));
    if (on_sale === 'true') query = query.not('previous_price', 'is', null);
    if (in_stock === 'true') query = query.gt('stock_available', 0);
    if (free_shipping === 'true') query = query.eq('shipping_fee', 0);

    if (country && country !== 'all') {
      query = query.or(`target_countries.cs.{${country}},show_to_all.eq.true`);
    }

    if (sort === 'price_asc') query = query.order('price', { ascending: true });
    else if (sort === 'price_desc') query = query.order('price', { ascending: false });
    else if (sort === 'popular') query = query.order('sales_count', { ascending: false });
    else if (sort === 'newest') query = query.order('created_at', { ascending: false });
    else if (sort === 'views') query = query.order('views_count', { ascending: false });
    else query = query.order('sales_count', { ascending: false });

    query = query.range(parseInt(offset), parseInt(offset) + parseInt(limit) - 1);

    const { data, error } = await query;
    if (error) return sendError(res, 500, 'Failed to load products: ' + error.message);

    let productsWithRatings = (data || []).map(p => {
      const reviews = p.reviews || [];
      const avg = reviews.length ? reviews.reduce((s, r) => s + r.rating, 0) / reviews.length : 0;
      return { ...p, avg_rating: parseFloat(avg.toFixed(1)), review_count: reviews.length, reviews: undefined };
    });

    if (min_rating) {
      productsWithRatings = productsWithRatings.filter(p => p.avg_rating >= parseFloat(min_rating));
    }
    if (sort === 'rating') {
      productsWithRatings.sort((a, b) => b.avg_rating - a.avg_rating);
    }

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
    // Increment view count (fire and forget)
    supabase.from('products').update({ views_count: (data.views_count || 0) + 1 }).eq('id', req.params.id).then(() => {});
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

// Upload image (base64) → Supabase Storage via service key
app.post('/api/upload', async (req, res) => {
  try {
    const { data: b64, folder = 'uploads' } = req.body;
    if (!b64) return sendError(res, 400, 'No image data provided');
    const base64Data = b64.replace(/^data:image\/\w+;base64,/, '');
    const buffer = Buffer.from(base64Data, 'base64');
    const isPng = b64.startsWith('data:image/png');
    const ext = isPng ? 'png' : 'jpg';
    const filename = `${folder}/${Date.now()}_${Math.random().toString(36).slice(2)}.${ext}`;
    const { error } = await supabase.storage
      .from('product-images')
      .upload(filename, buffer, { contentType: isPng ? 'image/png' : 'image/jpeg', upsert: true });
    if (error) return sendError(res, 500, 'Storage upload failed: ' + error.message);
    const url = `${SUPABASE_URL}/storage/v1/object/public/product-images/${filename}`;
    return sendSuccess(res, { url });
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

// Post product (seller or admin)
app.post('/api/products', requireAuthOrAdmin, async (req, res) => {
  try {
    const isAdminRequest = !!req.admin;
    const product = {
      ...req.body,
      id: uuidv4(),
      seller_id: isAdminRequest ? (req.body.seller_id || null) : req.user.id,
      status: isAdminRequest ? 'active' : 'pending_approval',
      sales_count: isAdminRequest ? (parseInt(req.body.sales_count) || 0) : 0,
      created_at: new Date().toISOString()
    };

    if (!isAdminRequest) {
      const { data: profile } = await supabase.from('profiles').select('role').eq('id', req.user.id).single();
      if (profile?.role === 'admin') product.status = 'active';
    }

    const { data, error } = await supabase.from('products').insert(product).select().single();
    if (error) return sendError(res, 500, 'Product posting failed: ' + error.message);
    return sendSuccess(res, data, 'Product posted successfully');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

// Update product
app.put('/api/products/:id', requireAuthOrAdmin, async (req, res) => {
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

app.post('/api/categories', requireAuthOrAdmin, async (req, res) => {
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

app.delete('/api/categories/:id', requireAuthOrAdmin, async (req, res) => {
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

    const orderId = Math.floor(100000 + Math.random() * 900000).toString();
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
    const { product_id, user_name, rating, comment, user_id, photo_url } = req.body;
    if (!product_id || !user_name || !rating) return sendError(res, 400, 'Product, name and rating are required');
    if (rating < 1 || rating > 5) return sendError(res, 400, 'Rating must be between 1 and 5');

    const { data, error } = await supabase.from('reviews').insert({
      id: uuidv4(), product_id, user_id: user_id || null, user_name,
      rating: parseInt(rating), comment: comment || null, photo_url: photo_url || null,
      approved: false, created_at: new Date().toISOString()
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

app.get('/api/vouchers/public', async (req, res) => {
  try {
    const now = new Date().toISOString();
    let query = supabase.from('vouchers').select('id, code, discount_type, discount_value, min_order, usage_limit, usage_count, expires_at').eq('active', true);
    const { data, error } = await query.order('created_at', { ascending: false });
    if (error) return sendError(res, 500, error.message);
    const valid = (data || []).filter(v => (!v.expires_at || new Date(v.expires_at) > new Date()) && (v.usage_limit == null || v.usage_count < v.usage_limit));
    return sendSuccess(res, valid);
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

app.post('/api/banners', requireAuthOrAdmin, async (req, res) => {
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

app.delete('/api/banners/:id', requireAuthOrAdmin, async (req, res) => {
  try {
    const { error } = await supabase.from('banners').delete().eq('id', req.params.id);
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, null, 'Banner deleted');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// ADMIN ROUTES
// ═════════════════════════════════════════════════════════════════════════════

app.get('/api/admin/products', requireAuthOrAdmin, async (req, res) => {
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

app.patch('/api/admin/products/:id/status', requireAuthOrAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    const { data, error } = await supabase.from('products').update({ status, updated_at: new Date().toISOString() }).eq('id', req.params.id).select().single();
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data, 'Product status updated');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.patch('/api/admin/products/:id/hide', requireAuthOrAdmin, async (req, res) => {
  try {
    const { hidden } = req.body;
    const { data, error } = await supabase.from('products').update({ hidden }).eq('id', req.params.id).select().single();
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data, `Product ${hidden ? 'hidden' : 'visible'}`);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.delete('/api/admin/products/:id', requireAuthOrAdmin, async (req, res) => {
  try {
    const { error } = await supabase.from('products').delete().eq('id', req.params.id);
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, null, 'Product deleted');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.get('/api/admin/orders', requireAuthOrAdmin, async (req, res) => {
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

app.patch('/api/admin/orders/:id/status', requireAuthOrAdmin, async (req, res) => {
  try {
    const { status, tracking_number, estimated_delivery } = req.body;
    const { data: order } = await supabase.from('orders').select('user_id').eq('id', req.params.id).single();
    const updatePayload = { status, updated_at: new Date().toISOString() };
    if (tracking_number !== undefined) updatePayload.tracking_number = tracking_number || null;
    if (estimated_delivery !== undefined) updatePayload.estimated_delivery = estimated_delivery || null;
    const { data, error } = await supabase.from('orders').update(updatePayload).eq('id', req.params.id).select().single();
    if (error) return sendError(res, 500, error.message);
    if (order?.user_id) {
      const msgs = {
        confirmed: 'Your order has been confirmed and is being prepared!',
        shipped: `Your order is on its way!${tracking_number ? ' Tracking: ' + tracking_number : ''}${estimated_delivery ? ' Est. delivery: ' + new Date(estimated_delivery).toLocaleDateString() : ''}`,
        completed: 'Your order has been delivered! Thank you for shopping with Zmafrdeal.',
        cancelled: 'Your order has been cancelled. Contact us if you have questions.'
      };
      await supabase.from('notifications').insert({ user_id: order.user_id, type: 'order_update', title: `Order ${status.charAt(0).toUpperCase() + status.slice(1)}`, message: msgs[status] || `Your order status has been updated to: ${status}`, read: false, created_at: new Date().toISOString() });
    }
    return sendSuccess(res, data, 'Order status updated');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

// Seller: update their own order status
app.patch('/api/seller/orders/:id/status', requireAuth, async (req, res) => {
  try {
    const { status } = req.body;
    const allowed = ['confirmed', 'shipped', 'completed', 'cancelled'];
    if (!status || !allowed.includes(status)) return sendError(res, 400, 'Invalid status. Allowed: ' + allowed.join(', '));
    // Verify this order belongs to this seller
    const { data: order, error: fetchErr } = await supabase.from('orders').select('id, seller_id, user_id, status').eq('id', req.params.id).single();
    if (fetchErr || !order) return sendError(res, 404, 'Order not found');
    if (order.seller_id !== req.user.id) return sendError(res, 403, 'Not your order');
    const { data, error } = await supabase.from('orders').update({ status, updated_at: new Date().toISOString() }).eq('id', req.params.id).select().single();
    if (error) return sendError(res, 500, error.message);
    // Notify buyer
    if (order.user_id) {
      const msgs = { confirmed: 'Your order has been confirmed by the seller!', shipped: 'Great news — your order has been shipped!', completed: 'Your order has been delivered. Enjoy your purchase!', cancelled: 'Your order was cancelled by the seller. Contact us for help.' };
      await supabase.from('notifications').insert({ user_id: order.user_id, type: 'order_update', title: `Order ${status.charAt(0).toUpperCase() + status.slice(1)}`, message: msgs[status], read: false, created_at: new Date().toISOString() });
    }
    return sendSuccess(res, data, 'Order status updated');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

// Seller: view return requests on their products
app.get('/api/seller/returns', requireAuth, async (req, res) => {
  try {
    const { data: orderRows } = await supabase.from('orders').select('id').eq('seller_id', req.user.id);
    const ids = (orderRows || []).map(o => o.id);
    if (!ids.length) return sendSuccess(res, []);
    const { data, error } = await supabase.from('return_requests').select('*, orders(id, total)').in('order_id', ids).order('created_at', { ascending: false });
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data || []);
  } catch (e) { return sendError(res, 500, e.message); }
});

// Seller: add a response to a return request
app.patch('/api/seller/returns/:id/respond', requireAuth, async (req, res) => {
  try {
    const { response } = req.body;
    if (!response) return sendError(res, 400, 'Response text is required');
    // Verify the return belongs to one of this seller's orders
    const { data: ret } = await supabase.from('return_requests').select('order_id').eq('id', req.params.id).single();
    if (!ret) return sendError(res, 404, 'Return request not found');
    const { data: order } = await supabase.from('orders').select('seller_id').eq('id', ret.order_id).single();
    if (!order || order.seller_id !== req.user.id) return sendError(res, 403, 'Not your return request');
    const { data, error } = await supabase.from('return_requests').update({ customer_response: response, updated_at: new Date().toISOString() }).eq('id', req.params.id).select().single();
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data, 'Response saved');
  } catch (e) { return sendError(res, 500, e.message); }
});

// Return requests
app.post('/api/return-requests', requireAuth, async (req, res) => {
  try {
    const { order_id, product_name, reason } = req.body;
    if (!order_id || !product_name || !reason) return sendError(res, 400, 'Order ID, product name and reason are required');
    const { data, error } = await supabase.from('return_requests').insert({
      order_id, user_id: req.user.id, product_name, reason, status: 'pending',
      created_at: new Date().toISOString(), updated_at: new Date().toISOString()
    }).select().single();
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data, 'Return request submitted');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

// User: fetch their own return requests
app.get('/api/return-requests', requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('return_requests')
      .select('*')
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false });
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data || []);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

// User: respond to an admin decision (accept or dispute)
app.post('/api/return-requests/:id/respond', requireAuth, async (req, res) => {
  try {
    const { response, comment } = req.body;
    if (!['accepted', 'disputed'].includes(response)) return sendError(res, 400, 'Response must be "accepted" or "disputed"');
    const newStatus = response === 'accepted' ? 'completed' : 'disputed';
    const { data, error } = await supabase
      .from('return_requests')
      .update({ customer_response: response, customer_comment: comment || null, status: newStatus, updated_at: new Date().toISOString() })
      .eq('id', req.params.id)
      .eq('user_id', req.user.id)
      .select()
      .single();
    if (error) return sendError(res, 500, error.message);
    if (!data) return sendError(res, 404, 'Return request not found');
    return sendSuccess(res, data, response === 'accepted' ? 'Return accepted' : 'Dispute submitted');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.get('/api/admin/return-requests', requireAuthOrAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase.from('return_requests').select('*, orders(id, total), profiles(full_name, email)').order('created_at', { ascending: false });
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data || []);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.patch('/api/admin/return-requests/:id', requireAuthOrAdmin, async (req, res) => {
  try {
    const { status, admin_notes } = req.body;
    const { data, error } = await supabase.from('return_requests').update({ status, admin_notes: admin_notes || null, updated_at: new Date().toISOString() }).eq('id', req.params.id).select().single();
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data, 'Return request updated');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.get('/api/admin/reviews', requireAuthOrAdmin, async (req, res) => {
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

app.patch('/api/admin/reviews/:id', requireAuthOrAdmin, async (req, res) => {
  try {
    const { approved } = req.body;
    const { data, error } = await supabase.from('reviews').update({ approved }).eq('id', req.params.id).select().single();
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data, `Review ${approved ? 'approved' : 'rejected'}`);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.delete('/api/admin/reviews/:id', requireAuthOrAdmin, async (req, res) => {
  try {
    const { error } = await supabase.from('reviews').delete().eq('id', req.params.id);
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, null, 'Review deleted');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.get('/api/admin/sellers', requireAuthOrAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase.from('sellers').select('*, profiles(full_name, email, banned, ban_reason)').order('created_at', { ascending: false });
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data || []);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.patch('/api/admin/sellers/:id/status', requireAuthOrAdmin, async (req, res) => {
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

app.get('/api/admin/analytics', requireAuthOrAdmin, async (req, res) => {
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
app.post('/api/admin/vouchers', requireAuthOrAdmin, async (req, res) => {
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

app.get('/api/admin/vouchers', requireAuthOrAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase.from('vouchers').select('*').order('created_at', { ascending: false });
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data || []);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.patch('/api/admin/vouchers/:id/toggle', requireAuthOrAdmin, async (req, res) => {
  try {
    const { data: v } = await supabase.from('vouchers').select('active').eq('id', req.params.id).single();
    if (!v) return sendError(res, 404, 'Voucher not found');
    const { data, error } = await supabase.from('vouchers').update({ active: !v.active }).eq('id', req.params.id).select().single();
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data, data.active ? 'Voucher activated' : 'Voucher deactivated');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.post('/api/admin/vouchers/:id/assign', requireAuthOrAdmin, async (req, res) => {
  try {
    const { user_id } = req.body;
    if (!user_id) return sendError(res, 400, 'User ID is required');
    const { data: v } = await supabase.from('vouchers').select('*').eq('id', req.params.id).single();
    if (!v) return sendError(res, 404, 'Voucher not found');
    const { data, error } = await supabase.from('user_vouchers').insert({ user_id, voucher_id: req.params.id, assigned_at: new Date().toISOString() }).select().single();
    if (error) return sendError(res, 500, error.message);
    await supabase.from('notifications').insert({ user_id, type: 'voucher', title: 'You have a new voucher!', message: `Use code ${v.code} to get ${v.discount_type === 'percent' ? v.discount_value + '% off' : 'SLL ' + v.discount_value + ' off'} your order${v.min_order ? ' (min order: SLL ' + v.min_order + ')' : ''}.${v.expires_at ? ' Expires: ' + new Date(v.expires_at).toLocaleDateString() : ''}`, read: false, created_at: new Date().toISOString() });
    return sendSuccess(res, data, 'Voucher assigned to user');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

// Send notification to a single user
app.post('/api/admin/notifications/send', requireAuthOrAdmin, async (req, res) => {
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

// Broadcast notification to ALL users
app.post('/api/admin/notifications/broadcast', requireAuthOrAdmin, async (req, res) => {
  try {
    const { type, title, message } = req.body;
    if (!title || !message) return sendError(res, 400, 'Title and message required');
    const { data: users, error: uErr } = await supabase.from('profiles').select('id');
    if (uErr) return sendError(res, 500, uErr.message);
    if (!users || !users.length) return sendSuccess(res, { count: 0 }, 'No users to notify');
    const now = new Date().toISOString();
    const rows = users.map(u => ({ user_id: u.id, type: type || 'admin_message', title, message, read: false, created_at: now }));
    const { error } = await supabase.from('notifications').insert(rows);
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, { count: rows.length }, `Broadcast sent to ${rows.length} users`);
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
app.get('/api/admin/settings', requireAuthOrAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase.from('site_settings').select('*').single();
    if (error) return sendError(res, 404, 'Settings not found');
    return sendSuccess(res, data);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.put('/api/admin/settings', requireAuthOrAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase.from('site_settings').upsert({ id: 1, ...req.body, updated_at: new Date().toISOString() }).select().single();
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data, 'Settings saved');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.post('/api/admin/clear-flash-sales', requireAuthOrAdmin, async (req, res) => {
  try {
    const { error } = await supabase
      .from('products')
      .update({ is_flash_sale: false, flash_sale_price: null, flash_sale_end: null, flash_sale_stock: 0 })
      .eq('is_flash_sale', true);
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, null, 'All flash sales cleared');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

// Messages (user to admin)
app.get('/api/messages', requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('messages').select('*').eq('user_id', req.user.id).order('created_at', { ascending: true });
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data || []);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.post('/api/messages', requireAuth, async (req, res) => {
  try {
    const { subject, message, photo_url } = req.body;
    if (!message && !photo_url) return sendError(res, 400, 'Message or photo is required');
    const insertData = { user_id: req.user.id, subject: subject || 'General Inquiry', message: message || '📷 Photo', status: 'unread', created_at: new Date().toISOString() };
    if (photo_url) insertData.photo_url = photo_url;
    const { data, error } = await supabase.from('messages').insert(insertData).select().single();
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data, 'Message sent to admin');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.get('/api/admin/users', requireAuthOrAdmin, async (req, res) => {
  try {
    const { role } = req.query;
    let query = supabase.from('profiles').select('*').order('created_at', { ascending: false });
    if (role) query = query.eq('role', role);
    const { data, error } = await query;
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data || []);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.post('/api/admin/users/:id/ban', requireAuthOrAdmin, async (req, res) => {
  try {
    const { reason } = req.body;
    const { error } = await supabase.from('profiles').update({ role: 'buyer', banned: true, ban_reason: reason || null }).eq('id', req.params.id);
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, null, 'User banned');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.post('/api/admin/sellers/:id/ban', requireAuthOrAdmin, async (req, res) => {
  try {
    const { reason } = req.body;
    await supabase.from('profiles').update({ banned: true, ban_reason: reason || null }).eq('id', req.params.id);
    await supabase.from('sellers').update({ status: 'suspended' }).eq('id', req.params.id);
    await supabase.from('notifications').insert({
      user_id: req.params.id, type: 'account',
      title: 'Seller Account Suspended',
      message: reason ? `Your seller account has been suspended. Reason: ${reason}` : 'Your seller account has been suspended. Please contact support for details.',
      read: false, created_at: new Date().toISOString()
    });
    return sendSuccess(res, null, 'Seller banned');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.post('/api/admin/sellers/:id/unban', requireAuthOrAdmin, async (req, res) => {
  try {
    await supabase.from('profiles').update({ banned: false, ban_reason: null, role: 'seller' }).eq('id', req.params.id);
    await supabase.from('sellers').update({ status: 'approved' }).eq('id', req.params.id);
    await supabase.from('notifications').insert({
      user_id: req.params.id, type: 'account',
      title: 'Seller Account Reinstated',
      message: 'Great news! Your seller account has been reinstated. You can now log in and manage your store.',
      read: false, created_at: new Date().toISOString()
    });
    return sendSuccess(res, null, 'Seller unbanned');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.post('/api/admin/users/:id/unban', requireAuthOrAdmin, async (req, res) => {
  try {
    const { error } = await supabase.from('profiles').update({ banned: false }).eq('id', req.params.id);
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, null, 'User unbanned');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.get('/api/admin/messages', requireAuthOrAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase.from('messages').select('*, profiles(full_name, email)').order('created_at', { ascending: false });
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, data || []);
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.patch('/api/admin/messages/:id/reply', requireAuthOrAdmin, async (req, res) => {
  try {
    const { reply } = req.body;
    if (!reply) return sendError(res, 400, 'Reply text is required');
    const { data: msg } = await supabase.from('messages').select('user_id').eq('id', req.params.id).single();
    const { data, error } = await supabase.from('messages').update({ reply, status: 'replied', replied_at: new Date().toISOString() }).eq('id', req.params.id).select().single();
    if (error) return sendError(res, 500, error.message);
    if (msg?.user_id) {
      await supabase.from('notifications').insert({ user_id: msg.user_id, type: 'admin_message', title: 'Support replied to your message', message: reply, read: false, created_at: new Date().toISOString() });
    }
    return sendSuccess(res, data, 'Reply sent');
  } catch (e) {
    return sendError(res, 500, e.message);
  }
});

app.delete('/api/admin/messages/:id', requireAuthOrAdmin, async (req, res) => {
  try {
    const { error } = await supabase.from('messages').delete().eq('id', req.params.id);
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, null, 'Message deleted');
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

// ── Bulk delete endpoints (admin only) ──────────────────────────
app.delete('/api/admin/bulk/products', requireAuthOrAdmin, async (req, res) => {
  try {
    const { error } = await supabase.from('products').delete().neq('id', '00000000-0000-0000-0000-000000000000');
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, null, 'All products deleted');
  } catch (e) { return sendError(res, 500, e.message); }
});

app.delete('/api/admin/bulk/orders', requireAuthOrAdmin, async (req, res) => {
  try {
    const { error } = await supabase.from('orders').delete().neq('id', '00000000-0000-0000-0000-000000000000');
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, null, 'All orders deleted');
  } catch (e) { return sendError(res, 500, e.message); }
});

app.delete('/api/admin/bulk/reviews', requireAuthOrAdmin, async (req, res) => {
  try {
    const { error } = await supabase.from('reviews').delete().neq('id', '00000000-0000-0000-0000-000000000000');
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, null, 'All reviews deleted');
  } catch (e) { return sendError(res, 500, e.message); }
});

app.delete('/api/admin/bulk/vouchers', requireAuthOrAdmin, async (req, res) => {
  try {
    await supabase.from('user_vouchers').delete().neq('id', '00000000-0000-0000-0000-000000000000');
    const { error } = await supabase.from('vouchers').delete().neq('id', '00000000-0000-0000-0000-000000000000');
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, null, 'All vouchers deleted');
  } catch (e) { return sendError(res, 500, e.message); }
});

app.delete('/api/admin/bulk/users', requireAuthOrAdmin, async (req, res) => {
  try {
    const adminKey = req.headers['x-admin-key'] || req.query.admin_key;
    const { error } = await supabase.from('profiles').delete().eq('role', 'user');
    if (error) return sendError(res, 500, error.message);
    return sendSuccess(res, null, 'All regular users deleted');
  } catch (e) { return sendError(res, 500, e.message); }
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
