from string import Template
from flask import url_for, g
from models import User
from app import app
import datetime


class TemplateManager(object):

    @staticmethod
    def escape_for_html_element_context(unsafe):
        """Escape unsafe input for use inside HTML tags

        Args:
            unsafe (str): Unsafe input string to be sanitized

        Returns:
            str: sanitized input string
        """
        unsafe = unsafe.replace("&", "&amp;")
        unsafe = unsafe.replace("<", "&lt;")
        unsafe = unsafe.replace(">", "&gt;")
        unsafe = unsafe.replace("\"", "&quot;")
        unsafe = unsafe.replace("'", "&#x27;")
        unsafe = unsafe.replace("/", "&#x2F;")
        return unsafe

    @staticmethod
    def get_register_template(errors=[]):
        escaped_errors = [
            TemplateManager.escape_for_html_element_context(e) for e in errors]

        register_template = TemplateManager.get_template(
            "register-template", {"form_target": url_for('register')})

        alerts = "\n".join(TemplateManager.get_template(
            "alert-template", {"alert_type": "alert-danger", "alert_content": e}) for e in escaped_errors)

        main_content = alerts + register_template

        main_template = TemplateManager.get_template(
            "simple-main-template", {"main_title": "Register", "main_content": main_content})

        return main_template

    @staticmethod
    def get_deregister_template(errors=[]):
        escaped_errors = [
            TemplateManager.escape_for_html_element_context(e) for e in errors]
        escaped_username = TemplateManager.escape_for_html_element_context(
            g.user.username)

        deregister_template = TemplateManager.get_template(
            "deregister-template",
            {"form_target": url_for('deregister'), 'csrf_token': g.get('csrf_token', '')})

        alerts = "\n".join(TemplateManager.get_template(
            "alert-template", {"alert_type": "alert-danger", "alert_content": e}) for e in escaped_errors)
        nav_links = "\n".join([TemplateManager.generate_nav_link(
            "Home", "/", active=True), TemplateManager.generate_nav_link("Messages", "messages")])

        main_content = alerts + deregister_template
        main_template = TemplateManager.get_template(
            "main-template",
            {
                "main_title": "Deregister",
                "main_content": main_content,
                "nav_items": nav_links,
                "username": escaped_username,
                'csrf_token': g.get('csrf_token', '')
            })

        return main_template


    @staticmethod
    def get_login_template(errors=[]):
        escaped_errors = [
            TemplateManager.escape_for_html_element_context(e) for e in errors]
 
        login_template = TemplateManager.get_template(
            "login-template", {"form_target": url_for('login')})

        alerts = "\n".join(TemplateManager.get_template(
            "alert-template", {"alert_type": "alert-danger", "alert_content": e}) for e in escaped_errors)

        main_content = alerts + login_template

        main_template = TemplateManager.get_template(
            "simple-main-template", {"main_title": "Login", "main_content": main_content})

        return main_template

    @staticmethod
    def get_index_template(posts, errors=[]):
        escaped_errors = [
            TemplateManager.escape_for_html_element_context(e) for e in errors]
        escaped_username = TemplateManager.escape_for_html_element_context(
            g.user.username)

        nav_links = "\n".join([TemplateManager.generate_nav_link(
            "Home", "/", active=True), TemplateManager.generate_nav_link("Messages", "messages")])
        if g.user.is_admin:
            nav_links += TemplateManager.generate_nav_link(
                "Administration", "administration")

        alerts = "\n".join(TemplateManager.get_template(
            "alert-template", {"alert_type": "alert-danger", "alert_content": e}) for e in escaped_errors)

        max_attachment_size = str(
            app.config['MAX_CONTENT_LENGTH'] / 1024 / 1024) + "MB"
        post_form = TemplateManager.get_template(
            "post-form-template",
            {
                "username": escaped_username,
                "form_target": url_for('index'),
                "max_attachment_size": max_attachment_size,
                'csrf_token': g.get(
                    'csrf_token',
                    '')})

        posts_content = ""
        for p in posts:
            escaped_content = TemplateManager.escape_for_html_element_context(
                p.content)
            author_user = User.get_user_by_id(p.author_id)
            author_name = author_user.username if author_user is not None else "[Deleted]"
            escaped_author_name = TemplateManager.escape_for_html_element_context(
                author_name)

            if not p.has_file():
                post_content = TemplateManager.get_template(
                    "post-plain-template",
                    {
                        "post_author": escaped_author_name,
                        "post_text": escaped_content,
                        "post_time": datetime.datetime.fromtimestamp(
                            p.timestamp)})
            else:
                post_file_src = "/api/files/{:s}".format(p.attachment_name)

                if p.is_image():
                    post_content = TemplateManager.get_template(
                        "post-image-template",
                        {
                            "post_author": escaped_author_name,
                            "post_text": escaped_content,
                            "post_image_src": post_file_src,
                            "post_time": datetime.datetime.fromtimestamp(
                                p.timestamp)})
                else:
                    post_content = TemplateManager.get_template(
                        "post-link-template",
                        {
                            "post_author": escaped_author_name,
                            "post_text": escaped_content,
                            "post_file_src": post_file_src,
                            "post_time": datetime.datetime.fromtimestamp(
                                p.timestamp)
                        })
            posts_content += post_content + "\n"

        main_content = alerts + post_form + posts_content

        main_template = TemplateManager.get_template(
            "main-template",
            {
                "main_title": "Posts",
                "main_content": main_content,
                "nav_items": nav_links,
                "username": escaped_username,
                'csrf_token': g.get('csrf_token', '')
            })

        return main_template

    @staticmethod
    def get_messages_template(messages, errors=[]):
        escaped_errors = [
            TemplateManager.escape_for_html_element_context(e) for e in errors]
        escaped_username = TemplateManager.escape_for_html_element_context(
            g.user.username)

        nav_links = "\n".join([TemplateManager.generate_nav_link(
            "Home", "/"), TemplateManager.generate_nav_link("Messages", "messages", active=True)])
        if g.user.is_admin:
            nav_links += TemplateManager.generate_nav_link(
                "Administration", "administration")

        alerts = "\n".join(TemplateManager.get_template(
            "alert-template", {"alert_type": "alert-danger", "alert_content": e}) for e in escaped_errors)

        max_attachment_size = str(
            app.config['MAX_CONTENT_LENGTH'] / 1024 / 1024) + "MB"
        message_form = TemplateManager.get_template(
            "message-form-template",
            {
                "username": escaped_username,
                "form_target": url_for('messages'),
                "max_attachment_size": max_attachment_size,
                'csrf_token': g.get('csrf_token','')
            })

        messages_content = ""
        for m in messages:
            escaped_content = TemplateManager.escape_for_html_element_context(
                m.content)

            author_user = User.get_user_by_id(m.author_id)
            author_name = author_user.username if author_user is not None else "[Deleted]"
            escaped_author_name = TemplateManager.escape_for_html_element_context(
                author_name)

            recipient_user = User.get_user_by_id(m.recipient_id)
            recipient_name = recipient_user.username if recipient_user is not None else "[Deleted]"
            escaped_recipient_name = TemplateManager.escape_for_html_element_context(
                recipient_name)

            message_content = ""
            if not m.has_file():
                message_content = TemplateManager.get_template(
                    "message-plain-template",
                    {
                        "message_author": escaped_author_name,
                        "message_recipient": escaped_recipient_name,
                        "message_text": escaped_content,
                        "message_time": datetime.datetime.fromtimestamp(
                            m.timestamp)})
            else:
                message_file_src = "/api/files/{:s}".format(m.attachment_name)
                if m.is_image():
                    message_content = TemplateManager.get_template(
                        "message-image-template",
                        {
                            "message_author": escaped_author_name,
                            "message_recipient": escaped_recipient_name,
                            "message_text": escaped_content,
                            "message_image_src": message_file_src,
                            "message_time": datetime.datetime.fromtimestamp(
                                m.timestamp)})
                else:
                    message_content = TemplateManager.get_template(
                        "message-link-template",
                        {
                            "message_author": escaped_author_name,
                            "message_recipient": escaped_recipient_name,
                            "message_text": escaped_content,
                            "message_file_src": message_file_src,
                            "message_time": datetime.datetime.fromtimestamp(
                                m.timestamp)})
            messages_content += message_content + "\n"

        main_content = alerts + message_form + messages_content

        main_template = TemplateManager.get_template(
            "main-template",
            {
                "main_title": "Messages",
                "main_content": main_content,
                "nav_items": nav_links,
                "username": escaped_username,
                'csrf_token': g.get('csrf_token','')
            })

        return main_template

    @staticmethod
    def get_administration_template(users, errors):
        escaped_errors = [
            TemplateManager.escape_for_html_element_context(e) for e in errors]
        escaped_username = TemplateManager.escape_for_html_element_context(
            g.user.username)

        nav_links = "\n".join(
            [
                TemplateManager.generate_nav_link(
                    "Home",
                    "/"),
                TemplateManager.generate_nav_link(
                    "Messages",
                    "messages"),
                TemplateManager.generate_nav_link(
                    "Administration",
                    "administration",
                    active=True)])

        alerts = "\n".join(TemplateManager.get_template(
            "alert-template", {"alert_type": "alert-danger", "alert_content": e}) for e in escaped_errors)

        user_list_group = ""
        for u in users:
            if u.is_admin:
                user_list_group += TemplateManager.get_template(
                    "administration-user-template",
                    {
                        "user_name": TemplateManager.escape_for_html_element_context(
                            u.username),
                        "group_badges": TemplateManager.get_template(
                            "administration-user-group-badge",
                            {
                                "group_name": "Admin"}),
                        "user_id": u.id,
                        "promote_button_class": "hidden",
                        "delete_button_class": "hidden"})
            else:
                user_list_group += TemplateManager.get_template(
                    "administration-user-template",
                    {
                        "user_name": TemplateManager.escape_for_html_element_context(
                            u.username),
                        "group_badges": "",
                        "user_id": u.id,
                        "promote_button_class": "",
                        "delete_button_class": ""})

        admin_main = TemplateManager.get_template(
            "administration-main-template", {
                "user_list_group": user_list_group, 'csrf_token': g.get(
                    'csrf_token', '')})

        main_content = alerts + admin_main

        main_template = TemplateManager.get_template(
            "main-template",
            {
                "main_title": "Administration",
                "main_content": main_content,
                "nav_items": nav_links,
                "username": escaped_username,
                'csrf_token': g.get('csrf_token','')
            })

        return main_template

    @staticmethod
    def generate_nav_link(text, target, active=False):
        return TemplateManager.get_template(
            "nav-link-template",
            {
                "nav_target": target,
                "nav_text": text,
                "nav_active": "active" if active else ""})

    @staticmethod
    def get_template(template_name, substitutions):
        raw_template = TemplateManager.templates.get(template_name)
        if raw_template is None:
            return None
        return Template(raw_template).safe_substitute(substitutions)

    templates = {"main-template":
                 """
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="">
    <meta name="author" content="">

    <title>Tweeter - ${main_title}</title>

    <link href="static/css/bootstrap.min.css" rel="stylesheet">
    <link href="static/css/starter-template.css" rel="stylesheet">
    <link href="static/css/tweeter.css" rel="stylesheet">
    <script src="static/js/tweeter.js"></script>
    <meta name="csrf-token" content="${csrf_token}"/>
</head>

<body>

    <nav class="navbar navbar-expand-md navbar-dark bg-dark fixed-top">
        <a class="navbar-brand" href="">Tweeter</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbar" aria-controls="navbar"
            aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>

        <div class="collapse navbar-collapse" id="navbar">
            <ul class="navbar-nav mr-auto">
                ${nav_items}
            </ul>
            <ul class="navbar-nav ml-auto">
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle" href="" id="navbarDropdownMenuLink" data-toggle="dropdown" aria-haspopup="true"
                        aria-expanded="false">
                        Logged in as ${username}
                    </a>
                    <div class="dropdown-menu" aria-labelledby="navbarDropdownMenuLink">
                        <a class="dropdown-item" href="#" id="logout_link">
                            Logout
                        </a>
                        <a class="dropdown-item" href="/deregister">
                            Delete my account
                        </a>
                    </div>
                </li>
            </ul>
        </div>
    </nav>

    <div class="container">
        ${main_content}
    </div>

    <script src="static/js/jquery-3.2.1.slim.min.js"></script>
    <script src="static/js/popper.min.js"></script>
    <script src="static/js/bootstrap.min.js"></script>
</body>

</html>
    """,
                 "simple-main-template":
                 """
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="">
    <meta name="author" content="">

    <title>Tweeter - ${main_title}</title>

    <link href="static/css/bootstrap.min.css" rel="stylesheet">
    <link href="static/css/starter-template.css" rel="stylesheet">
    <link href="static/css/tweeter.css" rel="stylesheet">
</head>

<body>
    <nav class="navbar navbar-expand-md navbar-dark bg-dark fixed-top">
        <a class="navbar-brand" href="">Tweeter</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbar" aria-controls="navbar"
            aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>

        <div class="collapse navbar-collapse" id="navbar">
            <ul class="navbar-nav mr-auto">
            </ul>
        </div>
    </nav>

    <div class="container">
        ${main_content}
    </div>

    <script src="static/js/jquery-3.2.1.slim.min.js"></script>
    <script src="static/js/popper.min.js"></script>
    <script src="static/js/bootstrap.min.js"></script>
</body>
</html>
    """,

                 "login-template":
                 """
<h4>You need to log in or <a href="register">create a new account</a></h4>
<form action="${form_target}" method="POST">
    <div class="form-group">
        <label for="username">Username</label>
        <input type="text" class="form-control" id="username" name="username" placeholder="">
    </div>
    <div class="form-group">
        <label for="password">Password</label>
        <input type="password" class="form-control" id="password" name="password" placeholder="">
    </div>
    <button type="submit" class="btn btn-primary">Login</button>
</form>
    """,

                 "register-template":
                 """
<h1>Create account</h1>
<form action="${form_target}" method="POST">
    <div class="form-group">
        <label for="username">Username</label>
        <input type="text" class="form-control" id="username" name="username" aria-describedby="usernameHelp" placeholder="">
        <small id="usernameHelp" class="form-text text-muted">Max 265 characters</small>
    </div>
    <div class="form-group">
        <label for="password">Password</label>
        <input type="password" class="form-control" id="password" name="password" aria-describedby="passwordHelp" placeholder="">
        <small id="passwordHelp" class="form-text text-muted">Must be at least 8 and maximum 256 characters</small>
    </div>
    <button type="submit" class="btn btn-primary">Register</button>
</form>
    """,
                "deregister-template":
                """
                <h4>Please enter your password to delete your account:</h4>
                <form action="${form_target}" method="POST">
                    <input type="hidden" name="csrf-token" value="${csrf_token}"/>
                    <div class="form-group">
                        <label for="user_password">Password:</label>
                        <input type="password" name="user_password" id="user_password"/>
                    </div>
                    <button type="submit" class="btn btn-danger">Delete my account</button>
                </form>
                """,
                 "post-plain-template":
                 """
<div class="card">
    <div class="card-body">
        <h6 class="card-subtitle mb-2 text-muted">Posted by ${post_author} at ${post_time}</h6>
        <p class="card-text">${post_text}</p>
    </div>
</div>
    """,

                 "post-image-template":
                 """
<div class="card">
    <a href="${post_image_src}">
        <img class="card-img-top post-image" src="${post_image_src}">
    </a>
    <div class="card-body">
        <h6 class="card-subtitle mb-2 text-muted">Posted by ${post_author} at ${post_time}</h6>
        <p class="card-text">${post_text}</p>
    </div>
</div>
    """,

                 "post-link-template":
                 """
<div class="card">
    <div class="card-body">
        <h6 class="card-subtitle mb-2 text-muted">Posted by ${post_author} at ${post_time}</h6>
        <p class="card-text">${post_text}</p>
        <a href="${post_file_src}">Attachment</a>
    </div>
</div>
    """,

                 "message-plain-template":
                 """
<div class="card">
    <div class="card-body">
        <h6 class="card-subtitle mb-2 text-muted">Sent by ${message_author} to ${message_recipient} at ${message_time}</h6>
        <p class="card-text">${message_text}</p>
    </div>
</div>
    """,

                 "message-image-template":
                 """
<div class="card">
    <a href="${message_image_src}">
        <img class="card-img-top post-image" src="${message_image_src}">
    </a>
    <div class="card-body">
        <h6 class="card-subtitle mb-2 text-muted">Sent by ${message_author} to ${message_recipient} at ${message_time}</h6>
        <p class="card-text">${message_text}</p>
    </div>
</div>
    """,

                 "message-link-template":
                 """
<div class="card">
    <div class="card-body">
        <h6 class="card-subtitle mb-2 text-muted">Sent by ${message_author} to ${message_recipient} at ${message_time}</h6>
        <p class="card-text">${message_text}</p>
        <a href="${message_file_src}">Attachment</a>
    </div>
</div>
    """,

                 "post-form-template":
                 """
<div class="card">
    <div class="card-body">
        <h4 class="card-title">Create new post</h4>
        <h6 class="card-subtitle mb-2 text-muted">Posting as ${username}</h6>
        <form action="${form_target}" method="POST" enctype="multipart/form-data">
            <input type="hidden" name="csrf-token" value="${csrf_token}"/>
            <div class="form-group">
			    <label for="post_content">Your post</label>
			    <textarea class="form-control" id="post_content" name="post_content" rows="3"></textarea>
			</div>
            <div class="form-row align-items-center">
                <div class="col-auto">
                    <label for="attachment">Attachment</label>
                    <input type="file" class="form-control-file" id="attachment" name="attachment" aria-describedby="attachmentHelp">
                    <small id="attachmentHelp" class="form-text text-muted">Max ${max_attachment_size}.</small>
                </div>
                <div class="col-auto">
                    <button type="submit" class="btn btn-primary">Submit</button>
                </div>
            </div>
        </form>
    </div>
</div>
    """,

                 "message-form-template":
                 """
<div class="card">
    <div class="card-body">
        <h4 class="card-title">Send a message</h4>
        <h6 class="card-subtitle mb-2 text-muted">Send from ${username}</h6>
        <form action="${form_target}" method="POST" enctype="multipart/form-data">
            <input type="hidden" name="csrf-token" value="${csrf_token}"/>
            <div class="form-group">
                <label for="message_recipient">Recipient</label>
                <input type="text" class="form-control" id="message_recipient" name="message_recipient" placeholder="">
            </div>
            <div class="form-group">
			    <label for="message_content">Your message</label>
			    <textarea class="form-control" id="message_content" name="message_content" rows="3"></textarea>
			</div>
            <div class="form-row align-items-center">
                <div class="col-auto">
                    <label for="attachment">Attachment</label>
                    <input type="file" class="form-control-file" id="attachment" name="attachment" aria-describedby="attachmentHelp">
                    <small id="attachmentHelp" class="form-text text-muted">Max ${max_attachment_size}.</small>
                </div>
                <div class="col-auto">
                    <button type="submit" class="btn btn-primary">Submit</button>
                </div>
            </div>
        </form>
    </div>
</div>
    """,

                 "administration-main-template":
                 """
<h1>Administration</h1>
<div class="form">
    <label for="admin_password_input">Please enter your password:</label>
    <input type="password" name="admin_password_input" id="admin_password_input"/>
</div>
<ul class="list-group">
    ${user_list_group}
</ul>
    """,

                 "administration-user-template":
                 """
<li class="list-group-item">
    <div class="row">
        <div class="col">
            ${user_name} ${group_badges}
        </div>
        <div class="col">
            <button data-userid="${user_id}" type="button" class="btn btn-primary btn-sm btn-promote ${promote_button_class}">
                Promote to admin
            </button>
            <button data-userid="${user_id}" type="button" class="btn btn-danger btn-sm btn-delete ${delete_button_class}">
                Delete user
            </button>
        </div>
    </div>
</li>
    """,

                 "administration-user-group-badge":
                 """
<span class="badge badge-primary">${group_name}</span>
    """,


                 "alert-template":
                 """
<div class="alert ${alert_type}" role="alert">
  ${alert_content}
</div>
    """,

                 "nav-link-template":
                 """
<li class="nav-item ${nav_active}">
    <a class="nav-link" href="${nav_target}">${nav_text}</a>
</li>
    """
                 }
