from flask import (
    Flask, render_template, request, jsonify, Response, redirect, url_for, flash, session, send_file
)
from werkzeug.utils import secure_filename
import subprocess
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_paginate import Pagination, get_page_parameter
from json import load
import pyodbc
from urllib.parse import quote_plus
import os
from models import db, User, Contact, SnippetMain, FileUploadMain
from aes_encryption import AES_Encryption
from datetime import datetime
from sqlalchemy.orm import joinedload
import time


app = Flask(__name__, static_url_path='/static')



# Update Snippet to SnippetMain and FileUpload to FileUploadMain
ITEMS_PER_PAGE = 12

def get_paginated_snippets(user, page):
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        query = SnippetMain.query.filter_by(user_id=user.id).order_by(SnippetMain.date_created.desc())  # Updated model
        snippets_pagination = query.paginate(page=page, per_page=ITEMS_PER_PAGE, error_out=False)
        return snippets_pagination

    # Return None if the user is not logged in
    return None


def get_snippets():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        return user.snippets
    return []


@app.route("/")
def home():
    return render_template('index.html', config=config)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('mainindex'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user and aes_encryption.aes_decrypt(user.password) == password:
            session['user_id'] = user.id
            flash("Logged in successfully!", "success")
            return redirect(url_for('mainindex'))
        else:
            flash("Invalid username or password.", "error")
            return render_template('login.html', invalid_credentials=True)

    return render_template('login.html')
    
@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if 'user_id' in session:
        return redirect(url_for('mainindex'))

    if request.method == 'POST':
        name = request.form.get('name').strip()
        email = request.form.get('email').strip()
        password = request.form.get('password').strip()

        existing_user = User.query.filter_by(username=email).first()
        if existing_user:
            flash("Email is already in use.", "error")
        else:
            encrypted_password = aes_encryption.aes_encrypt(password)
            new_user = User(username=email, password=encrypted_password, email=email)
            db.session.add(new_user)
            db.session.commit()
            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for('login'))

    return render_template('create-account.html')


@app.route("/reset_password", methods=['GET', 'POST'])
def reset_password():
    # Check if the user is logged in
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Get the current user
    user_id = session['user_id']
    user = User.query.get(user_id)
    if request.method == 'POST':
        old_password = request.form.get('old-password')
        new_password = request.form.get('new-password')
        confirm_new_password = request.form.get('confirm-new-password')

        # Verify that the old password matches the stored password
        if aes_encryption.aes_decrypt(user.password) != old_password:
            flash("Incorrect old password. Please try again.", "error")
            return redirect(url_for('reset_password'))

        # Check if the new password and confirmation match
        if new_password != confirm_new_password:
            flash("New password and confirmation do not match. Please try again.", "error")
            return redirect(url_for('reset_password'))

        # Update the user's password with the new one
        user.password = aes_encryption.aes_encrypt(new_password)
        db.session.commit()

        flash("Password reset successfully!", "success")
        return redirect(url_for('mainindex'))

    return render_template('resetpass.html')



# Define a custom error handler for 404 Not Found
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.route('/favicon.ico')
def favicon():
    return app.send_static_file('favicon.ico')


@app.route("/about_us")
def about_us():
    # Your code here
    return render_template('aboutus.html')

@app.route('/mainindex')
def mainindex():
    if 'user_id' in session:
        current_user = User.query.get(session['user_id'])

        if current_user:
            # Get the page number from the query parameters or use 1 as the default
            page_number = request.args.get(get_page_parameter(), 1, type=int)

            # Set the number of snippets to display per page
            per_page = 4  # Display 4 snippets per page

            # Query for the snippets
            snippets_query = SnippetMain.query.filter_by(user_id=current_user.id).order_by(SnippetMain.date_created.desc())  # Updated model

            # Handle the search query
            search_query = request.args.get('search', '')
            if search_query:
                snippets_query = snippets_query.filter(SnippetMain.title.contains(search_query))

            # Create a Pagination object
            snippets_pagination = Pagination(page=page_number, total=snippets_query.count(), per_page=per_page, css_framework='bootstrap4')

            # Get snippets for the current page
            snippets = snippets_query.offset((page_number - 1) * per_page).limit(per_page).all()

            # Calculate the total number of snippets for the user
            total_snippets = len(current_user.snippets)  # Calculate the total number of snippets

            # Get the latest 4 snippets
            latest_snippets = SnippetMain.query.filter_by(user_id=current_user.id).order_by(SnippetMain.date_created.desc()).limit(4).all()

            # Calculate the total number of pages for pagination
            total_pages = (total_snippets + per_page - 1) // per_page

            # Create the pagination range
            pagination_range = range(1, total_pages + 1)

            return render_template('mainindex.html', snippets=snippets, snippets_pagination=snippets_pagination, total_snippets=total_snippets, top_snippets=latest_snippets, pagination_range=pagination_range)  # Pass pagination_range to the template
        else:
            flash("User not found.", "error")
            return redirect(url_for('home'))
    else:
        flash("Please log in or sign up to access the main page.", "info")
        return redirect(url_for('home'))

@app.route('/mysnippets', methods=['GET'])
def mysnippets():
    if 'user_id' in session:
        current_user = User.query.get(session['user_id'])

        if current_user:
            page_number = request.args.get(get_page_parameter(), type=int, default=1)
            snippets_pagination = get_paginated_snippets(current_user, page_number)

            total_snippets = len(current_user.snippets)

            return render_template('mysnippets.html', snippets_pagination=snippets_pagination, total_snippets=total_snippets)
        else:
            flash("User not found.", "error")
            return redirect(url_for('home'))
    else:
        flash("Please log in to access your snippets.", "info")
        return redirect(url_for('home'))

# Update Snippet to SnippetMain and FileUpload to FileUploadMain
@app.route('/create_snippet', methods=['POST'])
def create_snippet():
    # Get form inputs
    title = request.form['title']
    description = request.form['description']
    privacy = request.form['privacy']

    # Check if a file was uploaded
    uploaded_file = request.files.get('file')

    # Check if the user is logged in
    if 'user_id' not in session:
        flash("Please log in to create a snippet.", "info")
        return redirect(url_for('login'))

    # Get the currently logged-in user
    user_id = session['user_id']
    current_user = User.query.get(user_id)

    # Create a new Snippet instance
    new_snippet = SnippetMain(title=title, description=description, user=current_user)  # Updated model

    # Set the snippet's privacy based on the form input
    if privacy == 'public':
        new_snippet.is_public = True

    # Save the snippet to the database
    db.session.add(new_snippet)
    db.session.commit()

    # Check if a file was uploaded
    if uploaded_file:
        # Process the uploaded file
        filename = secure_filename(uploaded_file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        uploaded_file.save(file_path)

        # Create a new FileUpload entry for the uploaded file
        new_upload = FileUploadMain(filename=filename, path=file_path, snippet=new_snippet)  # Updated model
        db.session.add(new_upload)
        db.session.commit()

    flash('Snippet created successfully.', 'success')
    return redirect(url_for('mainindex'))


@app.route("/profile")
def profile():
    # Fetch user data from the database, assuming you have a user object
    user = User.query.get(session.get('user_id'))
    
    if user:
        return render_template('profile.html', user=user)
    else:
        flash("User not found.", "error")
        return redirect(url_for('home'))








@app.route('/download_code_file/<int:snippet_id>/<int:file_id>')
def download_code_file(snippet_id, file_id):
    # Find the snippet and file upload by IDs
    snippet = SnippetMain.query.get(snippet_id)
    file_upload = FileUploadMain.query.get(file_id)

    if snippet and file_upload:
        # Check if the file is associated with the specified snippet
        if file_upload.snippet_id == snippet.id:
            return send_file(file_upload.path, as_attachment=True, download_name=file_upload.filename)
    
    flash("File not found.", "error")
    return redirect(url_for('view_snippet', snippet_id=snippet_id))









# Logout
@app.route("/logout")
def logout():
    if 'user_id' in session:
        session.pop('user_id', None)
        flash("Logged out successfully.", "success")
    return redirect(url_for('home'))


@app.route("/contact", methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')

        # Create a new contact record and add it to the database
        new_contact = Contact(name=name, email=email, message=message)
        db.session.add(new_contact)
        db.session.commit()

        flash("Thank you for your message!", "success")
        return redirect(url_for('home'))

    return render_template('contact.html')

@app.route('/view_snippet/<int:snippet_id>')
def view_snippet(snippet_id):
    snippet = db.session.get(SnippetMain,(snippet_id))
    if snippet:
        return render_template('view_snippet.html', snippet=snippet)
    else:
        flash("Snippet not found.", "error")
        return redirect(url_for('mainindex'))
    
@app.route('/delete_snippet/<int:snippet_id>', methods=['POST'])
def delete_snippet(snippet_id):
    snippet = SnippetMain.query.get(snippet_id)

    if snippet:
        # Delete associated file uploads first
        for file_upload in snippet.uploads:
            db.session.delete(file_upload)

        db.session.delete(snippet)
        db.session.commit()
        flash("Snippet and associated files deleted successfully.", "success")
    else:
        flash("Snippet not found.", "error")

    return redirect(url_for('mainindex'))


@app.route('/edit_snippet/<int:snippet_id>', methods=['GET', 'POST'])
def edit_snippet(snippet_id):
    # Get the snippet by ID
    snippet = SnippetMain.query.get(snippet_id)

    # Check if the snippet exists
    if not snippet:
        flash("Snippet not found.", "error")
        return redirect(url_for('mainindex'))

    # Check if the user is logged in
    if 'user_id' not in session:
        flash("Please log in to edit a snippet.", "info")
        return redirect(url_for('login'))

    # Get the currently logged-in user
    user_id = session['user_id']
    current_user = User.query.get(user_id)

    # Check if the user is the owner of the snippet
    if snippet.user != current_user:
        flash("You do not have permission to edit this snippet.", "error")
        return redirect(url_for('mainindex'))

    if request.method == 'POST':
        # Get form inputs
        title = request.form['title']
        description = request.form['description']
        privacy = request.form['privacy']
        new_file = request.files.get('new_file')

        # Update the snippet's properties
        snippet.title = title
        snippet.description = description
        snippet.is_public = (privacy == 'public')

        # Handle the new file upload if provided
        if new_file:
            # Check if a file was uploaded
            if new_file.filename != '':
                # Process the uploaded file
                filename = secure_filename(new_file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                new_file.save(file_path)

                # Update the existing file upload or create a new one
                if snippet.uploads:
                    # If the snippet already has a file, update it
                    existing_upload = snippet.uploads[0]  # Assuming there's only one file per snippet
                    existing_upload.filename = filename
                    existing_upload.path = file_path
                else:
                    # If the snippet doesn't have a file, create a new one
                    new_upload = FileUploadMain(filename=filename, path=file_path, snippet=snippet)
                    db.session.add(new_upload)

        # Commit the changes to the database
        db.session.commit()

        flash('Snippet updated successfully.', 'success')
        return redirect(url_for('view_snippet', snippet_id=snippet.id))

    return render_template('edit_snippet.html', snippet=snippet)



@app.route('/editor')
def editor():
    return render_template('python_editor.html')


@app.route('/run_code', methods=['POST'])
def run_python_code():
    data = request.get_json()
    python_code = data.get('code')

    try:
        # Use the `exec` function to execute the Python code
        exec_output = {}
        exec(python_code, {}, exec_output)

        # Get the standard output and standard error
        stdout = exec_output.get('stdout', '')
        stderr = exec_output.get('stderr', '')

        # Combine stdout and stderr into a single output string
        output = stdout + stderr

        return jsonify({'output': output})
    except Exception as e:
        return jsonify({'output': str(e)})

@app.route("/save_code", methods=["POST"])
def save_code():
    try:
        # Get the code and filename from the request
        code = request.form.get("code")
        filename = request.form.get("filename")

        # Specify the new directory where code will be saved
        save_directory = 'D:/WEBSITES/CODE-SNIPPET/files/python_editor'

        # Ensure the save directory exists; create it if necessary
        if not os.path.exists(save_directory):
            os.makedirs(save_directory)

        # Construct the full path to the saved file
        file_path = os.path.join(save_directory, filename)

        # Save the code to the file
        with open(file_path, "w") as file:
            file.write(code)

        return jsonify({"message": "Code saved successfully"})
    except Exception as e:
        return jsonify({"message": f"Error saving code: {str(e)}"})


def execute_code(code, language):
    if language == 'python':
        try:
            # Use subprocess to run Python code and capture the output
            result = subprocess.check_output(['python', '-c', code], stderr=subprocess.STDOUT, text=True)
            return result
        except subprocess.CalledProcessError as e:
            return str(e.output)
    elif language == 'javascript':
        # Implement code execution logic for JavaScript
        pass
    # Add support for other languages as needed
    else:
        return "Unsupported language"

def save_code_to_file(code, filename):
    try:
        # Open the file in write mode and write the code to it
        with open(filename, 'w') as file:
            file.write(code)
        return "Code saved successfully"
    except Exception as e:
        return f"Error saving code: {str(e)}"

# Function to execute Python code and return the output
def execute_python_code(code):
    try:
        # Execute the Python code using subprocess
        process = subprocess.Popen(
            ['python', '-c', code],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        stdout, stderr = process.communicate()
        
        if process.returncode == 0:
            return f"Output:\n{stdout}"
        else:
            return f"Error:\n{stderr}"
    except Exception as e:
        return str(e)

@app.route('/run_code_sse')
def run_code_sse():
    code = request.args.get('code', '')

    def generate():
        try:
            # Execute the Python code and capture the output
            result = execute_python_code(code)

            # Yield the result to the SSE client without the "Output:" prefix
            for line in result.splitlines():
                yield f"data: {line}\n\n"
        except Exception as e:
            # Handle any exceptions and send an error message
            yield f"data: Error: {str(e)}\n\n"

    return Response(generate(), content_type='text/event-stream')

@app.route("/public_snippets")
def public_snippets():
    # Query for all public snippets
    public_snippets = SnippetMain.query.filter_by(is_public=True).order_by(SnippetMain.date_created.desc()).all()  # Updated model

    return render_template('public_snippets.html', public_snippets=public_snippets)





if __name__ == "__main__":
    app.run(debug=True)