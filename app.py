from flask import Flask, render_template, request, redirect, url_for, flash
import requests
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired, Email, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import current_user, login_required, LoginManager, UserMixin, login_user
import random

app = Flask(__name__)
app.config['SECRET_KEY'] = '1234'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://tjlcmuvb:keaT9EXdsmDvhaagbFX9u9lQOe4FYhr7@peanut.db.elephantsql.com/tjlcmuvb'

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'danger'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(120))
    caught_pokemon = db.relationship('PokemonCatched', backref='user', lazy=True)
    wins = db.Column(db.Integer, default=0)
    losses = db.Column(db.Integer, default=0)
    draws = db.Column(db.Integer, default=0)

class Pokemon(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    hp = db.Column(db.Integer)
    defense = db.Column(db.Integer)
    attack = db.Column(db.Integer)
    front_shiny = db.Column(db.String(255))
    abilities = db.Column(db.String(255))

    def __init__(self, name, hp, defense, attack, front_shiny, abilities):
        self.name = name
        self.hp = hp
        self.defense = defense
        self.attack = attack
        self.front_shiny = front_shiny
        self.abilities = abilities

class PokemonCatched(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    pokemon_id = db.Column(db.Integer, db.ForeignKey('pokemon.id'), nullable=False)
    pokemon = db.relationship('Pokemon', backref='catches')

    def __init__(self, user_id, pokemon_id):
        self.user_id = user_id
        self.pokemon_id = pokemon_id

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=80)])
    email = StringField('Email', validators=[InputRequired(), Email(), Length(max=120)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=120)])

class EditProfileForm(FlaskForm):
    new_username = StringField('Username', render_kw={'readonly': True})
    email = StringField('Email', render_kw={'readonly': True})  # Mark email as read-only
    new_password = PasswordField('New Password', validators=[Length(min=6, max=120)])

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('welcome'))
        else:
            flash('Invalid username or password. Please try again.', 'danger')

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()

        if existing_user:
            flash('Username or email already exists. Please choose another.', 'danger')
        else:
            hashed_password = generate_password_hash(password, method='sha256')
            new_user = User(username=username, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Signup successful! Please log in.', 'success')
            return redirect(url_for('login'))

    return render_template('signup.html', form=form)

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()

    if request.method == 'GET':
        # Pre-fill the form fields with the current user's information
        form.new_username.data = current_user.username
        form.email.data = current_user.email
        form.new_password.data = current_user.password
    if form.validate_on_submit():
        new_username = form.new_username.data
        new_password = form.new_password.data

        if new_username:
            current_user.username = new_username

        if new_password:
            hashed_password = generate_password_hash(new_password, method='sha256')
            current_user.password = hashed_password
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        login_user(current_user)

        return redirect(url_for('edit_profile'))

    return render_template('edit_profile.html', form=form)

@app.route('/welcome')
@login_required
def welcome():
    username = current_user.username
    return render_template('welcome.html', username=username)

@app.route('/pokemon_search', methods=['GET', 'POST'])
def pokemon_search():
    if request.method == 'POST':
        pokemon_name = request.form['pokemon_name']
        
        # Check if the Pokemon is already in the database
        pokemon = Pokemon.query.filter(Pokemon.name.ilike(pokemon_name)).first()
        
        if pokemon:
            # Check if the Pokemon has already been caught by any user
            user_has_catched_pokemon = PokemonCatched.query \
                .filter_by(pokemon_id=pokemon.id) \
                .first()
            
            if user_has_catched_pokemon:
                flash('This Pokemon has already been caught by another user!', 'danger')
                return redirect(url_for('pokemon_search'))

            # Check if the user has reached the catch limit of 5
            if len(current_user.caught_pokemon) >= 5:
                flash('You have reached the maximum limit of caught Pokemon (5).', 'danger')
                return redirect(url_for('pokemon_search'))

            # Add the caught Pokemon to the user's collection
            new_catched_pokemon = PokemonCatched(user_id=current_user.id, pokemon_id=pokemon.id)
            db.session.add(new_catched_pokemon)
            db.session.commit()

            name = pokemon.name
            hp = pokemon.hp
            defense = pokemon.defense
            attack = pokemon.attack
            front_shiny = pokemon.front_shiny
            abilities = pokemon.abilities.split(',')
        else:
            api_url = f"https://pokeapi.co/api/v2/pokemon/{pokemon_name.lower()}"
            response = requests.get(api_url)

            if response.status_code == 200:
                pokemon_data = response.json()
                name = pokemon_data['name'].capitalize()
                hp = pokemon_data['stats'][0]['base_stat']
                defense = pokemon_data['stats'][2]['base_stat']
                attack = pokemon_data['stats'][1]['base_stat']
                front_shiny = pokemon_data['sprites']['front_shiny']
                abilities = [ability['ability']['name'] for ability in pokemon_data['abilities']]

                # Create a new Pokemon in the database
                new_pokemon = Pokemon(
                    name=name,
                    hp=hp,
                    defense=defense,
                    attack=attack,
                    front_shiny=front_shiny,
                    abilities=','.join(abilities)
                )
                db.session.add(new_pokemon)
                db.session.commit()
            else:
                error_message = "Pokemon not found. Please try again."
                return render_template('pokemon_search.html', error_message=error_message)

        return render_template(
            'pokemon_search.html',
            name=name,
            hp=hp,
            defense=defense,
            attack=attack,
            front_shiny=front_shiny,
            abilities=abilities
        )

    return render_template('pokemon_search.html')

@app.route('/my_pokemon')
@login_required
def my_pokemon():
    # Query the database to fetch all Pokemon caught by the user
    user_catched_pokemon = PokemonCatched.query \
        .filter_by(user_id=current_user.id) \
        .join(Pokemon, PokemonCatched.pokemon_id == Pokemon.id) \
        .all()
    return render_template('my_pokemon.html', user_catched_pokemon=user_catched_pokemon)

@app.route('/release_pokemon/<int:pokemon_id>', methods=['POST'])
@login_required
def release_pokemon(pokemon_id):
    # Check if the Pokemon with the given ID belongs to the current user
    caught_pokemon = PokemonCatched.query \
        .filter_by(user_id=current_user.id, pokemon_id=pokemon_id) \
        .first()

    if caught_pokemon:
        # Remove the caught Pokemon from the user's collection
        db.session.delete(caught_pokemon)
        db.session.commit()
        flash('Pokemon released successfully!', 'success')
    else:
        flash('You cannot release a Pokemon that you do not own.', 'danger')

    return redirect(url_for('my_pokemon'))

@app.route('/hall_of_fame')
@login_required
def hall_of_fame():
    # Query the database to fetch all users
    users = User.query.all()
    
    # Create a dictionary to store user and their caught Pokemon sets
    user_pokemon_sets = {}

    # Fetch caught Pokemon sets for each user and store them in the dictionary
    for user in users:
        caught_pokemon = PokemonCatched.query \
            .filter_by(user_id=user.id) \
            .join(Pokemon, PokemonCatched.pokemon_id == Pokemon.id) \
            .all()
        user_pokemon_sets[user] = caught_pokemon

    return render_template('hall_of_fame.html', user_pokemon_sets=user_pokemon_sets)

@app.route('/attack/<int:target_user_id>', methods=['GET'])
@login_required
def attack(target_user_id):
    # Fetch the target user and their caught Pokemon
    target_user = User.query.get(target_user_id)
    target_pokemon = target_user.caught_pokemon

    # Fetch the current user's caught Pokemon
    current_user_pokemon = current_user.caught_pokemon

    # Determine the number of battles (minimum of user's and target's Pokemon count)
    num_battles = min(len(target_pokemon), len(current_user_pokemon))

    # Initialize variables to track total HP lost for each user
    current_user_hp_lost = 0

    # Initialize a list to store battle results
    battle_results = []

    # Shuffle the lists of Pokemon
    random.shuffle(target_pokemon)
    random.shuffle(current_user_pokemon)

    # Simulate battles
    for i in range(num_battles):
        current_pokemon = current_user_pokemon[i].pokemon
        target_pokemon_instance = target_pokemon[i].pokemon

        # Calculate HP lost for each Pokemon
        current_hp_lost = current_pokemon.attack - target_pokemon_instance.defense

        # Update total HP lost for each user
        current_user_hp_lost += current_hp_lost

        # Append battle result to the list
        battle_results.append(
            {
                'current_pokemon': current_pokemon,
                'target_pokemon': target_pokemon_instance,
                'current_hp_lost': current_hp_lost
            }
        )

    # Determine the winner
    winner = current_user if current_user_hp_lost > 0 else target_user
    # Update the user's win-lose-draw record
    if current_user_hp_lost > 0:
        winner = current_user
        loser = target_user
    elif current_user_hp_lost < 0:
        winner = target_user
        loser = current_user
    else:
        # It's a draw
        winner = None
        loser = None

    # Update the win, lose, and draw columns for both users
    if winner:
        winner.wins += 1
        loser.losses += 1
    else:
        # It's a draw
        current_user.draws += 1
        target_user.draws += 1

    # Commit the changes to the database
    db.session.commit()


    return render_template(
        'fight.html',
        winner=winner,
        battle_results=battle_results,
        current_user_hp_lost=current_user_hp_lost,
        target_user=target_user  # Add this line to pass the target_user to the template
    )

if __name__ == '__main__':


    
    app.run(debug=True)
