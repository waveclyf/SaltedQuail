import os
from datetime import datetime
from functools import wraps

from flask import Flask, render_template, abort, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
import stripe
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# ---------------------------------------------------------------------------
# SECRET_KEY — this signs the session cookie, which is what admin auth relies
# on (session["is_admin"]). There is NO safe hardcoded fallback for this: if
# it's predictable, anyone can forge an admin session cookie and skip the
# login screen entirely. In production you MUST set SECRET_KEY as an env var.
# For local dev only, we fall back to a random key generated per process
# (sessions just won't survive a restart, which is fine locally).
# ---------------------------------------------------------------------------
_secret_key = os.environ.get("SECRET_KEY")
_is_production = os.environ.get("FLASK_ENV") == "production" or os.environ.get("VERCEL") == "1"
if not _secret_key:
    if _is_production:
        raise RuntimeError(
            "SECRET_KEY environment variable is not set. Refusing to start in "
            "production with an insecure/default key — set SECRET_KEY in your "
            "Vercel project's environment variables."
        )
    import secrets as _secrets
    _secret_key = _secrets.token_hex(32)
    app.logger.warning(
        "SECRET_KEY not set — using a random per-process key for local dev. "
        "Set SECRET_KEY explicitly before deploying."
    )
app.secret_key = _secret_key

# Render (and Heroku) hand out DATABASE_URL as postgres://, but SQLAlchemy 1.4+/2.x
# wants postgresql://. Falls back to a local SQLite file for local dev if unset.
database_url = os.environ.get("DATABASE_URL", "sqlite:///dev.db")
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# ---------------------------------------------------------------------------
# Session cookie hardening
# ---------------------------------------------------------------------------
app.config.update(
    SESSION_COOKIE_SECURE=_is_production,   # only send cookie over HTTPS in prod
    SESSION_COOKIE_HTTPONLY=True,           # JS can't read the cookie
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=1800,        # 30 min idle timeout
)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, default_limits=[])


@app.after_request
def set_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if _is_production:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

stripe.api_key = os.environ.get("STRIPE_SECRET_KEY")
STRIPE_PUBLISHABLE_KEY = os.environ.get("STRIPE_PUBLISHABLE_KEY")
DOMAIN = os.environ.get("DOMAIN", "http://localhost:5000")  # e.g. https://saltedquail.com in production

# ---------------------------------------------------------------------------
# Product catalog — small and fixed for now, so it stays a plain dict rather
# than a DB table. Move this into a Product model once you need more than a
# handful of items or want admins to edit it without a redeploy.
# ---------------------------------------------------------------------------
PRODUCTS = {
    1: {
        "id": 1, "name": "T-Shirt", "price_cents": 2200, "image": "t-shirt.jpg",
        "extra_images": ["t-shirt1.jpg"],
        "description": "Premium quality 100% cotton t-shirt. Breathable fabric, "
                        "perfect for casual wear, and tailored for a modern fit.",
        "options": {"label": "Size", "choices": ["1XL", "2XL", "3XL", "4XL", "5XL"]},
    },
    2: {
        "id": 2, "name": "Coffee Mug", "price_cents": 1000, "image": "mug.jpg",
        "description": "High-quality ceramic coffee mug. Microwave and dishwasher safe, "
                        "featuring an ergonomic handle to enjoy your morning brew.",
    },
    3: {
        "id": 3, "name": "Truth, Prayers and Confirmation", "price_cents": 2000, "image": "book.jpg",
        "extra_images": ["book1.jpg"],
        "description": "Being conscious, deliberate, and intentional at building the SaltedQuail "
                        "business for the glory of God. Know that Saltedquail LLC is more than a "
                        "publishing brand — it's a faith base business, and a Christ-centered mission. "
                        "As a believer, and a published author, who sales creative writings, and "
                        "timeless Biblical truths to encourage intentional living in faith. The focus "
                        "is to build a community where we can continue to learn, share, and grow in "
                        "Christ. Dive into short devotionals, reflections, and articles that bring "
                        "Scripture into everyday life. Whether you're seeking encouragement, wisdom, "
                        "or a deeper understanding of God from the Word, our Insights are here to "
                        "guide you.",
        "purchasable": False,
    },
    4: {
        "id": 4, "name": "Cap", "price_cents": 2500, "image": "cap.jpg",
        "description": "Adjustable logo printed baseball cap with a curved brim and breathable "
                     "A comfortable, everyday fit for sunny days out. Available in 5 varieties of shades",
        "options": {"label": "Colour", "choices": ["Red", "Blue", "Black", "White", "Green"]},
    },
}

# ---------------------------------------------------------------------------
# Tax / handling — applied on top of the item subtotal at checkout.
# ---------------------------------------------------------------------------
TAX_RATE = 0.09              # 9% of the item subtotal
HANDLING_FEE_CENTS = 500     # flat $5.00 handling fee


def compute_order_totals(items):
    """Given cart items, return (subtotal_cents, tax_cents, handling_cents, total_cents)."""
    subtotal_cents = sum(item["line_total_cents"] for item in items)
    if not items:
        return 0, 0, 0, 0
    tax_cents = round(subtotal_cents * TAX_RATE)
    handling_cents = HANDLING_FEE_CENTS
    total_cents = subtotal_cents + tax_cents + handling_cents
    return subtotal_cents, tax_cents, handling_cents, total_cents


# ---------------------------------------------------------------------------
# Database models
# ---------------------------------------------------------------------------
class Admin(db.Model):
    __tablename__ = "admins"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Order(db.Model):
    __tablename__ = "orders"
    id = db.Column(db.Integer, primary_key=True)
    stripe_session_id = db.Column(db.String(255), unique=True, nullable=False)
    customer_email = db.Column(db.String(255))
    customer_name = db.Column(db.String(255))
    customer_phone = db.Column(db.String(50))
    shipping_line1 = db.Column(db.String(255))
    shipping_line2 = db.Column(db.String(255))
    shipping_city = db.Column(db.String(100))
    shipping_state = db.Column(db.String(100))
    shipping_zip = db.Column(db.String(20))
    shipping_country = db.Column(db.String(100))
    total_cents = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default="paid")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    items = db.relationship("OrderItem", backref="order", cascade="all, delete-orphan")


class OrderItem(db.Model):
    __tablename__ = "order_items"
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id"), nullable=False)
    product_id = db.Column(db.Integer, nullable=False)
    product_name = db.Column(db.String(255), nullable=False)
    unit_price_cents = db.Column(db.Integer, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)


@app.template_filter("usd")
def usd_filter(cents):
    return f"${cents / 100:,.2f}"


# ---------------------------------------------------------------------------
# Cart helpers (still session-based — carts are pre-purchase and disposable,
# so there's no need to put them in Postgres)
# ---------------------------------------------------------------------------
def get_cart():
    return session.setdefault("cart", {})


def get_cart_items():
    """Cart entries are keyed as "<product_id>|<variant>" so that, e.g., a 2XL
    and a 3XL t-shirt sit in the cart as two separate lines. `variant` is ""
    for products with no options (unchanged behaviour for Mug/Book)."""
    cart = get_cart()
    items = []
    for key, qty in cart.items():
        pid_str, _, variant = key.partition("|")
        product = PRODUCTS.get(int(pid_str)) if pid_str.isdigit() else None
        if not product:
            continue
        options = product.get("options")
        # Guard against a stale cart entry referencing an option that no
        # longer exists (e.g. the catalog was edited after items were added).
        if variant and (not options or variant not in options["choices"]):
            continue
        variant_label = options["label"] if (options and variant) else None
        line_item_name = f"{product['name']} ({variant_label}: {variant})" if variant else product["name"]
        items.append({
            "id": product["id"],
            "key": key,
            "name": product["name"],
            "variant": variant,
            "variant_label": variant_label,
            "line_item_name": line_item_name,
            "image": product["image"],
            "price_cents": product["price_cents"],
            "quantity": qty,
            "line_total_cents": product["price_cents"] * qty,
        })
    return items


def get_cart_count():
    return sum(get_cart().values())


MAX_QTY_PER_ITEM = 20


def parse_quantity(raw, default=1):
    """Safely parse a quantity from form data, clamped to a sane range.

    request.form values are attacker-controlled — a direct POST (bypassing
    the HTML <input min/max>) could send a non-numeric or huge value, which
    used to raise an unhandled ValueError (500 error) or set an absurd
    quantity. This clamps to [1, MAX_QTY_PER_ITEM] and never raises.
    """
    try:
        qty = int(raw)
    except (TypeError, ValueError):
        return default
    return max(1, min(qty, MAX_QTY_PER_ITEM))


@app.context_processor
def inject_cart_count():
    return {"cart_count": get_cart_count()}


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)
    return wrapped


# ---------------------------------------------------------------------------
# Storefront routes
# ---------------------------------------------------------------------------
@app.route("/")
def home():
    return render_template("home.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/terms")
def terms():
    return render_template("terms.html")


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.route("/refund-policy")
def refund_policy():
    return render_template("refund_policy.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/product/<int:product_id>")
def product_details(product_id):
    product = PRODUCTS.get(product_id)
    if not product:
        abort(404)
    return render_template("product_details.html", product=product)


@app.route("/cart")
def cart():
    items = get_cart_items()
    subtotal_cents, tax_cents, handling_cents, total_cents = compute_order_totals(items)
    return render_template(
        "cart.html",
        items=items,
        subtotal_cents=subtotal_cents,
        tax_cents=tax_cents,
        handling_cents=handling_cents,
        total_cents=total_cents,
        tax_rate_pct=int(round(TAX_RATE * 100)),
    )


@app.route("/cart/add/<int:product_id>", methods=["POST"])
def cart_add(product_id):
    product = PRODUCTS.get(product_id)
    if not product:
        abort(404)
    if not product.get("purchasable", True):
        # Not yet on sale (e.g. book still being finished) — refuse even if
        # someone bypasses the disabled UI with a direct POST.
        return redirect(url_for("product_details", product_id=product_id))

    variant = ""
    options = product.get("options")
    if options:
        variant = (request.form.get("variant") or "").strip()
        # Server-side backstop in case the <select required> is bypassed
        # (e.g. a direct POST) — refuse to add a variant product without a
        # valid, in-catalog choice rather than silently guessing one.
        if variant not in options["choices"]:
            return redirect(url_for("product_details", product_id=product_id))

    cart = get_cart()
    key = f"{product_id}|{variant}"
    qty = parse_quantity(request.form.get("quantity"), default=1)
    new_qty = cart.get(key, 0) + qty
    cart[key] = min(new_qty, MAX_QTY_PER_ITEM)
    session.modified = True
    return redirect(url_for("cart"))


@app.route("/cart/update/<path:key>", methods=["POST"])
def cart_update(key):
    cart = get_cart()
    raw_qty = request.form.get("quantity", "")
    try:
        requested_qty = int(raw_qty)
    except (TypeError, ValueError):
        requested_qty = 1
    if requested_qty <= 0:
        cart.pop(key, None)
    else:
        cart[key] = min(requested_qty, MAX_QTY_PER_ITEM)
    session.modified = True
    return redirect(url_for("cart"))


@app.route("/cart/remove/<path:key>", methods=["POST"])
def cart_remove(key):
    cart = get_cart()
    cart.pop(key, None)
    session.modified = True
    return redirect(url_for("cart"))


@app.route("/cart/clear", methods=["POST"])
def cart_clear():
    session["cart"] = {}
    session.modified = True
    return redirect(url_for("cart"))


# ---------------------------------------------------------------------------
# Checkout / Stripe
# ---------------------------------------------------------------------------
@app.route("/checkout")
def checkout():
    items = get_cart_items()
    if not items:
        return redirect(url_for("cart"))
    subtotal_cents, tax_cents, handling_cents, total_cents = compute_order_totals(items)
    return render_template(
        "checkout.html",
        items=items,
        subtotal_cents=subtotal_cents,
        tax_cents=tax_cents,
        handling_cents=handling_cents,
        total_cents=total_cents,
        tax_rate_pct=int(round(TAX_RATE * 100)),
    )


REQUIRED_SHIPPING_FIELDS = (
    "full_name", "email", "phone",
    "address_line1", "city", "state", "zip_code", "country",
)


@app.route("/create-checkout-session", methods=["POST"])
@limiter.limit("10 per minute")
def create_checkout_session():
    items = get_cart_items()
    if not items:
        return redirect(url_for("cart"))

    shipping_info = {field: request.form.get(field, "").strip() for field in (
        "full_name", "email", "phone",
        "address_line1", "address_line2", "city", "state", "zip_code", "country",
    )}

    # Server-side backstop in case the browser's own "required" validation is
    # bypassed (e.g. a direct POST). address_line2 is the only optional field.
    if not all(shipping_info[field] for field in REQUIRED_SHIPPING_FIELDS):
        return redirect(url_for("checkout"))

    line_items = [{
        "price_data": {
            "currency": "usd",
            "product_data": {"name": item["line_item_name"]},
            "unit_amount": item["price_cents"],
        },
        "quantity": item["quantity"],
    } for item in items]

    _, tax_cents, handling_cents, _ = compute_order_totals(items)
    if tax_cents:
        line_items.append({
            "price_data": {
                "currency": "usd",
                "product_data": {"name": f"Tax ({int(round(TAX_RATE * 100))}%)"},
                "unit_amount": tax_cents,
            },
            "quantity": 1,
        })
    if handling_cents:
        line_items.append({
            "price_data": {
                "currency": "usd",
                "product_data": {"name": "Handling fee"},
                "unit_amount": handling_cents,
            },
            "quantity": 1,
        })

    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=line_items,
            mode="payment",
            customer_email=shipping_info["email"],
            metadata=shipping_info,
            success_url=f"{DOMAIN}/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{DOMAIN}/cart",
        )
    except Exception as e:
        app.logger.error(f"Stripe session creation failed: {e}")
        return redirect(url_for("checkout"))

    return redirect(checkout_session.url, code=303)


def _save_order_if_new(session_id, customer_email, total_cents, line_items, shipping_info=None):
    if Order.query.filter_by(stripe_session_id=session_id).first():
        return
    shipping_info = shipping_info or {}
    order = Order(
        stripe_session_id=session_id,
        customer_email=customer_email,
        total_cents=total_cents,
        status="paid",
        customer_name=shipping_info.get("full_name") or None,
        customer_phone=shipping_info.get("phone") or None,
        shipping_line1=shipping_info.get("address_line1") or None,
        shipping_line2=shipping_info.get("address_line2") or None,
        shipping_city=shipping_info.get("city") or None,
        shipping_state=shipping_info.get("state") or None,
        shipping_zip=shipping_info.get("zip_code") or None,
        shipping_country=shipping_info.get("country") or None,
    )
    for item in line_items:
        order.items.append(OrderItem(
            product_id=item.get("id", 0),
            product_name=item["name"],
            unit_price_cents=item["price_cents"],
            quantity=item["quantity"],
        ))
    db.session.add(order)
    db.session.commit()


@app.route("/success")
def success():
    # This is a best-effort confirmation for the customer's browser. The
    # Stripe webhook below is the source of truth — it fires even if the
    # customer closes the tab before this page loads.
    session_id = request.args.get("session_id")
    if session_id:
        try:
            checkout_session = stripe.checkout.Session.retrieve(session_id)
            if checkout_session.payment_status == "paid":
                # Use the line items Stripe actually charged, not the live
                # session cart — the customer may have edited/cleared their
                # cart between paying and landing back on this page, which
                # would otherwise save the wrong products against this order.
                stripe_line_items = stripe.checkout.Session.list_line_items(session_id)
                line_items = [{
                    "id": 0,
                    "name": li["description"],
                    "price_cents": (li["amount_total"] // li["quantity"]) if li["quantity"] else 0,
                    "quantity": li["quantity"],
                } for li in stripe_line_items["data"]
                  if not (li["description"] or "").startswith(("Tax (", "Handling fee"))]
                _save_order_if_new(
                    session_id,
                    checkout_session.customer_details.email if checkout_session.customer_details else None,
                    checkout_session.amount_total,
                    line_items,
                    dict(checkout_session.metadata) if checkout_session.metadata else {},
                )
        except Exception as e:
            app.logger.error(f"Could not verify Stripe session: {e}")

    session["cart"] = {}
    session.modified = True
    return render_template("success.html")


@app.route("/stripe-webhook", methods=["POST"])
@csrf.exempt
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")
    webhook_secret = os.environ.get("STRIPE_WEBHOOK_SECRET")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
    except Exception as e:
        app.logger.error(f"Webhook signature verification failed: {e}")
        return "", 400

    if event["type"] == "checkout.session.completed":
        checkout_session = event["data"]["object"]
        session_id = checkout_session["id"]
        if not Order.query.filter_by(stripe_session_id=session_id).first():
            stripe_line_items = stripe.checkout.Session.list_line_items(session_id)
            line_items = [{
                "name": li["description"],
                "price_cents": (li["amount_total"] // li["quantity"]) if li["quantity"] else 0,
                "quantity": li["quantity"],
            } for li in stripe_line_items["data"]
              if not (li["description"] or "").startswith(("Tax (", "Handling fee"))]
            _save_order_if_new(
                session_id,
                checkout_session.get("customer_details", {}).get("email"),
                checkout_session["amount_total"],
                line_items,
                checkout_session.get("metadata", {}),
            )

    return "", 200


# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------
@app.route("/admin/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def admin_login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        admin = Admin.query.filter_by(username=username).first()
        if admin and admin.check_password(password):
            session["is_admin"] = True
            session["admin_username"] = admin.username
            return redirect(url_for("admin_dashboard"))
        error = "Invalid username or password."
    return render_template("admin_login.html", error=error)


@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    session.pop("admin_username", None)
    return redirect(url_for("admin_login"))


@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    total_revenue_cents = db.session.query(
        db.func.coalesce(db.func.sum(Order.total_cents), 0)
    ).scalar()
    order_count = Order.query.count()
    return render_template(
        "admin_dashboard.html",
        total_revenue_cents=total_revenue_cents,
        order_count=order_count,
    )


@app.route("/admin/orders")
@admin_required
def orders():
    all_orders = Order.query.order_by(Order.created_at.desc()).all()
    return render_template("orders.html", orders=all_orders)


# ---------------------------------------------------------------------------
# `flask create-admin` — run this once (locally or in the Render shell) to
# create the first admin login. See DEPLOYMENT.md.
# ---------------------------------------------------------------------------
@app.cli.command("create-admin")
def create_admin():
    import getpass
    username = input("Admin username: ")
    password = getpass.getpass("Admin password: ")
    with app.app_context():
        if Admin.query.filter_by(username=username).first():
            print("That username already exists.")
            return
        admin = Admin(username=username, password_hash=generate_password_hash(password))
        db.session.add(admin)
        db.session.commit()
    print(f"Admin '{username}' created.")


# NOTE: db.create_all() used to run here. Schema is now managed by
# Flask-Migrate instead — run `flask db upgrade` to create/update tables.
# See DEPLOYMENT.md for the one-time setup and the workflow for future changes.

if __name__ == "__main__":
    app.run(debug=True)