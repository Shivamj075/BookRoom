import os, json

from flask import Flask, session, redirect, render_template, request, jsonify, flash, url_for
from flask_session import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

from flask_dance.contrib.github import make_github_blueprint, github
# from flask_dance.consumer.backend.sqla import OAuthConsumerMixin, SQLAlchemyBackend
from flask_dance.consumer import oauth_authorized
from werkzeug.security import check_password_hash, generate_password_hash

import requests


app = Flask(__name__)


app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Set up database

# database engine object from SQLAlchemy that manages connections to the database
engine = create_engine("postgres://pqisqwmaijqmjn:c71dc3d6cc20220798d01933fe530141795327490a07a10be1e03ab8b6a0a994@ec2-107-21-200-103.compute-1.amazonaws.com:5432/da3qv0c22k7gr2")

# create a 'scoped session' that ensures different users' interactions with the
# database are kept separate
db = scoped_session(sessionmaker(bind=engine))

github_blueprint = make_github_blueprint(client_id='272ae4c6200eb46e5df2', client_secret='31eb790efc21a79b3fc7c892c46feaa997762a22')


app.register_blueprint(github_blueprint, url_prefix='/github_login')
# db = SQLAlchemy(app)
# login_manager = LoginManager(app)

@app.route("/")
def index():

    return render_template("index.html")

@app.route('/github')
def github_login():
    if not github.authorized:
        return redirect(url_for('github.login'))

    account_info = github.get('/user')

    if account_info.ok:
        account_info_json = account_info.json()

        return '<h1>Your Github name is {}'.format(account_info_json['login'])

    return '<h1>Request failed!</h1>'


@app.route("/login", methods=["GET", "POST"])
def login():

    session.clear()

    username = request.form.get("username")

    if request.method == "POST":

        rows = db.execute("SELECT * FROM users WHERE username = :username",
                            {"username": username})
        
        result = rows.fetchone()

        # Ensure username exists and password is correct
        if result == None or not check_password_hash(result[2], request.form.get("password")):
            return render_template("error.html", message="invalid username and/or password")

        # Remember which user has logged in
        session["user_id"] = result[0]
        session["user_name"] = result[1]

        return redirect("/")

    else:
        return render_template("login.html")


@app.route("/logout")
def logout():

    session.clear()

    # Redirect user to login form
    return redirect("/login")

@app.route("/register", methods=["GET", "POST"])
def register():

    session.clear()
    
    if request.method == "POST":

        userCheck = db.execute("SELECT * FROM users WHERE username = :username",
                          {"username":request.form.get("username")}).fetchone()

        if userCheck:
            return render_template("error.html", message="username already exist")

        elif not request.form.get("password") == request.form.get("confirmation"):
            return render_template("error.html", message="passwords didn't match")
        
        # user password hash to store in DATABASE
        hashedPassword = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)
        
        db.execute("INSERT INTO users (username, password) VALUES (:username, :password)",
                            {"username":request.form.get("username"), 
                             "password":hashedPassword})

        # changes to database
        db.commit()

        flash('Account created', 'info')

        # Redirect user to login page
        return redirect("/login")

    else:
        return render_template("register.html")

@app.route("/search", methods=["GET"])
def search():
   
    if not request.args.get("book"):
        return render_template("error.html", message="you must provide a book details.")

    # Add a wildcard in input
    query = "%" + request.args.get("book") + "%"

    query = query.title()
    
    rows = db.execute("SELECT isbn, title, author, year FROM books WHERE \
                        isbn LIKE :query OR title LIKE :query OR author LIKE :query LIMIT 15",
                        {"query": query})
    
    if rows.rowcount == 0:
        return render_template("error.html", message="we can't find the book with this description.")
    
    books = rows.fetchall()

    return render_template("results.html", books=books)

@app.route("/detail/<isbn>",methods=["GET","POST"])
def detail(isbn):

    book = db.execute("SELECT id FROM books WHERE isbn = :isbn",
                        {"isbn": isbn})
    if request.method == "POST":

        currentUser = session["user_id"]
        
        rating = request.form.get("rating")
        comment = request.form.get("comment")
        
        bookId = book.fetchone() 
        bookId = bookId[0]

        if db.execute("SELECT * FROM reviews WHERE user_id = :user_id AND book_id = :book_id",
                    {"user_id": currentUser,
                     "book_id": bookId}).rowcount == 1:
            
            flash('You already submitted a review for this book', 'info')
            return redirect("/detail/" + isbn)

        db.execute("INSERT INTO reviews (user_id, book_id, comment, rating) VALUES \
                    (:user_id, :book_id, :comment, :rating)",
                    {"user_id": currentUser, "book_id": bookId, 
                    "comment": comment, "rating": rating})

        db.commit()

        flash('Thanks for giving your valuable review!', 'warning')

        return redirect("/detail/" + isbn)
    
    # Take the book ISBN and redirect to his page (GET)
    else:

        row = db.execute("SELECT isbn, title, author, year FROM books WHERE \
                        isbn = :isbn",
                        {"isbn": isbn})

        bookInfo = row.fetchall()

        """ GOODREADS reviews """
        
        # Query the api with key and ISBN as parameters
        query = requests.get("https://www.goodreads.com/book/review_counts.json",
                params={"key": "w7j29ui7OI4u9O7Kw0Ifg", "isbns": isbn})

        response = query.json()

        response = response['books'][0]

        bookInfo.append(response)

        row = db.execute("SELECT id FROM books WHERE isbn = :isbn",
                        {"isbn": isbn})

        book = row.fetchone() 
        print(book)
        book = book[0]

        results = db.execute("SELECT users.username, comment, rating FROM users INNER JOIN reviews \
            ON users.id = reviews.user_id WHERE book_id = :book", {"book": book})

        reviews = results.fetchall()

        return render_template("books.html", bookInfo=bookInfo, reviews=reviews)


