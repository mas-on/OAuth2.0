from flask import Flask, render_template, request, redirect,jsonify, url_for, flash
app = Flask(__name__)

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem, User

#import session for key
from flask import session as login_session
import random, string

# IMPORTS FOR oauth2
#from oauth2client.client import flow_from_clientsecrets
#from oauth2client.file import Storage
#from oauth2client.tools import run_flow
#from oauth2client.client import credentials_from_clientsecrets_and_code
#from oauth2client.client import FlowExchangeError

import google.oauth2.credentials
# import google_auth_oauthlib.flow
from google.oauth2 import id_token
from google.auth.transport import requests as g_requests

import httplib2
import json
from flask import make_response
import requests

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu Application"


#Connect to Database and create database session
engine = create_engine('sqlite:///restaurantmenuwithusers.db',connect_args={'check_same_thread': False})
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


#JSON APIs to view Restaurant Information
@app.route('/restaurant/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    items = session.query(MenuItem).filter_by(restaurant_id = restaurant_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(restaurant_id, menu_id):
    Menu_Item = session.query(MenuItem).filter_by(id = menu_id).one()
    return jsonify(Menu_Item = Menu_Item.serialize)

@app.route('/restaurant/JSON')
def restaurantsJSON():
    restaurants = session.query(Restaurant).all()
    return jsonify(restaurants= [r.serialize for r in restaurants])


#Show all restaurants
@app.route('/')
@app.route('/restaurant/')
def showRestaurants():
  restaurants = session.query(Restaurant).order_by(asc(Restaurant.name))  
  print login_session
  if 'username' not in login_session:
	return render_template('publicrestaurants.html', restaurants = restaurants)
  else:
	return render_template('restaurants.html', restaurants = restaurants)

#Create a new restaurant
@app.route('/restaurant/new/', methods=['GET','POST'])
def newRestaurant():
  if 'username' not in login_session:
	flash('You cannot add restaurants')
	return redirect(url_for('showRestaurants'))
	
  if request.method == 'POST':
      newRestaurant = Restaurant(name = request.form['name'], user_id = login_session['userid'])
      session.add(newRestaurant)
      flash('New Restaurant %s Successfully Created' % newRestaurant.name)
      session.commit()
      return redirect(url_for('showRestaurants'))
  else:
      return render_template('newRestaurant.html')

#Edit a restaurant
@app.route('/restaurant/<int:restaurant_id>/edit/', methods = ['GET', 'POST'])
def editRestaurant(restaurant_id):
  editedRestaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
  if 'username' not in login_session or editedRestaurant.user_id != login_session['userid']:
	flash('You cannot edit this restaurant')
	return redirect(url_for('showRestaurants'))
	
  if request.method == 'POST':
      if request.form['name']:
        editedRestaurant.name = request.form['name']
        flash('Restaurant Successfully Edited %s' % editedRestaurant.name)
        return redirect(url_for('showRestaurants'))
  else:
    return render_template('editRestaurant.html', restaurant = editedRestaurant)


#Delete a restaurant
@app.route('/restaurant/<int:restaurant_id>/delete/', methods = ['GET','POST'])
def deleteRestaurant(restaurant_id):
  restaurantToDelete = session.query(Restaurant).filter_by(id = restaurant_id).one()
  if 'username' not in login_session or restaurantToDelete.user_id != login_session['userid']:
	flash('You cannot delete this restaurant')
	return redirect(url_for('showRestaurants'))
	
  if request.method == 'POST':
    session.delete(restaurantToDelete)
    flash('%s Successfully Deleted' % restaurantToDelete.name)
    session.commit()
    return redirect(url_for('showRestaurants', restaurant_id = restaurant_id))
  else:
    return render_template('deleteRestaurant.html',restaurant = restaurantToDelete)

#Show a restaurant menu
@app.route('/restaurant/<int:restaurant_id>/')
@app.route('/restaurant/<int:restaurant_id>/menu/')
def showMenu(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()	
    items = session.query(MenuItem).filter_by(restaurant_id = restaurant_id).all()
    creator = getUserInfo(restaurant.user_id)
    if 'username' not in login_session or creator.id != login_session['userid']:	
		return render_template('publicmenu.html', items = items, restaurant = restaurant, creator= creator)
    else:
		return render_template('menu.html', items = items, restaurant = restaurant, creator= creator)
     


#Create a new menu item
@app.route('/restaurant/<int:restaurant_id>/menu/new/',methods=['GET','POST'])
def newMenuItem(restaurant_id):
  restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
  if 'username' not in login_session or restaurant.user_id != login_session['userid']:
	flash('You cannot add menu items')
	return redirect(url_for('showMenu', restaurant_id = restaurant_id))
		
  if request.method == 'POST':
	newItem = MenuItem(name = request.form['name'], description = request.form['description'], price = request.form['price'], course = request.form['course'], restaurant_id = restaurant_id, user_id = restaurant.user_id)
	session.add(newItem)
	session.commit()
	flash('New Menu %s Item Successfully Created' % (newItem.name))
	return redirect(url_for('showMenu', restaurant_id = restaurant_id))
  else:
	return render_template('newmenuitem.html', restaurant_id = restaurant_id)

#Edit a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/edit', methods=['GET','POST'])
def editMenuItem(restaurant_id, menu_id):
    editedItem = session.query(MenuItem).filter_by(id = menu_id).one()
    if 'username' not in login_session or editedItem.user_id != login_session['userid']:
		flash('You cannot edit this menu item')
		return redirect(url_for('showMenu', restaurant_id = restaurant_id))
	
    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['price']:
            editedItem.price = request.form['price']
        if request.form['course']:
            editedItem.course = request.form['course']
        session.add(editedItem)
        session.commit() 
        flash('Menu Item Successfully Edited')
        return redirect(url_for('showMenu', restaurant_id = restaurant_id))
    else:
        return render_template('editmenuitem.html', restaurant_id = restaurant_id, menu_id = menu_id, item = editedItem)


#Delete a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/delete', methods = ['GET','POST'])
def deleteMenuItem(restaurant_id,menu_id):
    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()	
    itemToDelete = session.query(MenuItem).filter_by(id = menu_id).one() 
    if 'username' not in login_session or itemToDelete.user_id != login_session['userid']:
		flash('You cannot delete this menu item')
		return redirect(url_for('showMenu', restaurant_id = restaurant_id))
		
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Menu Item Successfully Deleted')
        return redirect(url_for('showMenu', restaurant_id = restaurant_id))
    else:
        return render_template('deleteMenuItem.html', item = itemToDelete)

#create a session token
@app.route('/login')
def showLogin():
	state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
	login_session['state'] = state
	return render_template('login.html', STATE=state)


#create oauth2 flow	
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    
	#verify google token from client side
    tokens = request.json
	
    print tokens
	
    try:
		# Specify the CLIENT_ID of the app that accesses the backend:
		# checks The value of aud in the ID token is equal to one of your app's client ID
		idinfo = id_token.verify_oauth2_token(tokens['id_token'], g_requests.Request(), CLIENT_ID)
		
		if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
			raise ValueError('Wrong issuer.')					
		
		# ID token is valid. Get the user's Google Account ID from the decoded token.		
		google_id = idinfo['sub']			
		
		stored_token = login_session.get('id_token')
		stored_google_id = login_session.get('google_id')		
		if stored_token is not None and google_id == stored_google_id:
			response = make_response(json.dumps('Current user is already connected.'), 200)
			response.headers['Content-Type'] = 'application/json'
			return response

		# Store the id token in the session for later use.
		login_session['id_token'] = tokens['id_token']
		login_session['access_token'] = tokens['access_token']
		login_session['google_id'] = google_id
		login_session['username'] = idinfo['name']
		login_session['picture'] = idinfo['picture']
		login_session['email'] = idinfo['email']
		
		#check if user exists in db
		db_userid = getUserID(login_session.get('email'))		
		if db_userid is None:
			db_userid = createUser(login_session)
		login_session["userid"] = db_userid
		print '       user_id=', db_userid

		output = ''
		output += '<h1>Welcome, '
		output += login_session['username']
		output += '!</h1>'
		output += '<img src="'
		output += login_session['picture']
		output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
		flash("you are now logged in as %s" % login_session['username'])
		print "done!"
		return output
		
    except ValueError as e:
		# Invalid token
		print str(e)
		response = make_response(json.dumps(str(e)), 401)
		response.headers['Content-Type'] = 'application/json'
		return response    
	
	
# User Helper Functions

def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None	
	

# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    token = login_session.get('access_token')
    if token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response						
		
    print 'In gdisconnect access token is %s', token
    print 'User name is: '
    print login_session['username']    

    result = requests.post('https://oauth2.googleapis.com/revoke',
		params={'token': token},
		headers = {'content-type': 'application/x-www-form-urlencoded'})
	
    print 'result is '
    print result
    status_code = getattr(result, 'status_code')
    print status_code
    if status_code == 200:
        del login_session['id_token']
        del login_session['access_token']
        del login_session['google_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session["userid"]
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

if __name__ == '__main__':
  app.secret_key = 'super_secret_key'
  app.debug = True
  
  import os 
  os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1' #for testing without ssl
  
  app.run(host = '0.0.0.0', port = 5000)
