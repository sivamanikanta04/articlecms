"""
Routes and views for the flask application.
"""

from datetime import datetime
from flask import render_template, flash, redirect, request, session, url_for
from werkzeug.urls import url_parse
from config import Config
from FlaskWebProject import app, db
from FlaskWebProject.forms import LoginForm, PostForm
from flask_login import current_user, logout_user, login_required
import msal
import uuid

imageSourceUrl = 'https://' + app.config['BLOB_ACCOUNT'] + '.blob.core.windows.net/' + app.config['BLOB_CONTAINER'] + '/'

@app.route('/')
@app.route('/home')
@login_required
def home():
    return render_template(
        'index.html',
        title='Home Page',
        posts=[]
    )

@app.route('/new_post', methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm(request.form)
    return render_template(
        'post.html',
        title='Create Post',
        imageSource=imageSourceUrl,
        form=form
    )

@app.route('/post/<int:id>', methods=['GET', 'POST'])
@login_required
def post(id):
    form = PostForm(formdata=request.form)

    return render_template(
        'post.html',
        title='Edit Post',
        imageSource=imageSourceUrl,
        form=form
    )

@app.route('/login', methods=['GET', 'POST'])
def login():

    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = LoginForm()

    if form.validate_on_submit():

        username = form.username.data
        password = form.password.data

        # FAILED LOGIN ATTEMPT
        if password != "password":

            flash('Invalid username or password')

            # LOG FAILED LOGIN ATTEMPT
            app.logger.warning(f"FAILED LOGIN ATTEMPT: Username '{username}'")

            return redirect(url_for('login'))

        # SUCCESSFUL LOGIN
        app.logger.info(f"SUCCESSFUL LOGIN: User '{username}' logged in")

        flash(f'Welcome {username}!')

        return redirect(url_for('home'))

    session["state"] = str(uuid.uuid4())
    auth_url = _build_auth_url(scopes=Config.SCOPE, state=session["state"])

    return render_template('login.html', title='Sign In', form=form, auth_url=auth_url)


@app.route(Config.REDIRECT_PATH)
def authorized():

    if request.args.get('state') != session.get("state"):
        return redirect(url_for("home"))

    if "error" in request.args:
        return render_template("auth_error.html", result=request.args)

    if request.args.get('code'):

        cache = _load_cache()

        result = _build_msal_app(cache=cache).acquire_token_by_authorization_code(
            request.args['code'],
            scopes=Config.SCOPE,
            redirect_uri=url_for("authorized", _external=True)
        )

        if "error" in result:
            return render_template("auth_error.html", result=result)

        session["user"] = result.get("id_token_claims")

        _save_cache(cache)

    return redirect(url_for('home'))


@app.route('/logout')
def logout():

    logout_user()

    if session.get("user"):

        session.clear()

        return redirect(
            Config.AUTHORITY + "/oauth2/v2.0/logout" +
            "?post_logout_redirect_uri=" + url_for("login", _external=True)
        )

    return redirect(url_for('login'))


def _load_cache():

    cache = msal.SerializableTokenCache()

    if session.get("token_cache"):
        cache.deserialize(session["token_cache"])

    return cache


def _save_cache(cache):

    if cache.has_state_changed:
        session["token_cache"] = cache.serialize()


def _build_msal_app(cache=None, authority=None):

    return msal.ConfidentialClientApplication(
        Config.CLIENT_ID,
        authority=authority or Config.AUTHORITY,
        client_credential=Config.CLIENT_SECRET,
        token_cache=cache
    )


def _build_auth_url(authority=None, scopes=None, state=None):

    return _build_msal_app(authority=authority).get_authorization_request_url(
        scopes or [],
        state=state,
        redirect_uri=url_for("authorized", _external=True)
    )
