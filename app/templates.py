from string import Template
from flask import url_for

class TemplateManager(object):
    @staticmethod
    def get_register_template(errors=[]):
        login_template = TemplateManager.get_template("register-template", {"form_target" : url_for('register'), "form_method" : "POST"})

        nav_links = "\n".join([TemplateManager.generate_nav_link("Home", "/", False), TemplateManager.generate_nav_link("Messages", "messages", False)])

        alerts = "\n".join(TemplateManager.get_template("alert-template", {"alert_type" : "alert-danger", "alert_content" : e}) for e in errors)

        main_content = alerts + login_template

        main_template = TemplateManager.get_template("main-template", {"main_title" : "Register", "main_content" : main_content, "user_menu_display" : "none", "nav_items" : nav_links})

        return main_template


    @staticmethod
    def get_login_template(errors=[]):
        login_template = TemplateManager.get_template("login-template", {"form_target" : url_for('login'), "form_method" : "POST"})

        nav_links = "\n".join([TemplateManager.generate_nav_link("Home", "/", False), TemplateManager.generate_nav_link("Messages", "messages", False)])

        alerts = "\n".join(TemplateManager.get_template("alert-template", {"alert_type" : "alert-danger", "alert_content" : e}) for e in errors)

        main_content = alerts + login_template

        main_template = TemplateManager.get_template("main-template", {"main_title" : "Login", "main_content" : main_content, "user_menu_display" : "none", "nav_items" : nav_links})

        return main_template

    @staticmethod
    def generate_nav_link(text, target, active):
        return TemplateManager.get_template("nav-link-template", {"nav_target" : target, "nav_text" : text, "nav_active" : "active" if active else ""})

    @staticmethod
    def get_template(template_name, substitutions):
        raw_template = TemplateManager.templates.get(template_name)
        if raw_template is None:
            return None
        return Template(raw_template).safe_substitute(substitutions)

#TODO: load dynamically on startup from files in templates/
    templates = { "main-template" : 
    """
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="">
    <meta name="author" content="">

    <title>Tweeter - ${main_title}</title>

    <!-- Bootstrap core CSS -->
    <link href="static/css/bootstrap.min.css" rel="stylesheet">

    <!-- Custom styles for this template -->
    <link href="static/css/starter-template.css" rel="stylesheet">
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
            <ul class="navbar-nav ml-auto" style="display: ${user_menu_display};">
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle" href="" id="navbarDropdownMenuLink" data-toggle="dropdown" aria-haspopup="true"
                        aria-expanded="false">
                        Logged in as ${username}
                    </a>
                    <div class="dropdown-menu" aria-labelledby="navbarDropdownMenuLink">
                        <a class="dropdown-item" href="logout">Logout</a>
                        <a class="dropdown-item" href="deregister">Delete my account</a>
                    </div>
                </li>
            </ul>
        </div>
    </nav>

    <div class="container">
        ${main_content}
    </div>
    <!-- /.container -->


    <!-- Bootstrap core JavaScript
    ================================================== -->
    <!-- Placed at the end of the document so the pages load faster -->
    <script src="https://code.jquery.com/jquery-3.2.1.slim.min.js" integrity="sha384-KJ3o2DKtIkvYIK3UENzmM7KCkRr/rE9/Qpg6aAZGJwFDMVNA/GpGFF93hXpG5KkN"
        crossorigin="anonymous"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.11.0/umd/popper.min.js" integrity="sha384-b/U6ypiBEHpOf/4+1nzFpr53nxSS+GLCkfwBdFNTxtclqqenISfwAzpKaMNFNmj4"
        crossorigin="anonymous"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/js/bootstrap.min.js" integrity="sha384-h0AbiXch4ZDo7tp9hKZ4TsHbi047NrKGLO3SEJAg45jXxnGIfYzk4Si90RDIqNm1"
        crossorigin="anonymous"></script>
    <!-- IE10 viewport hack for Surface/desktop Windows 8 bug -->
    <!--<script src="/js/ie10-viewport-bug-workaround.js"></script>-->
</body>

</html>
    """,

    "login-template" :
    """
<h4>You need to log in or <a href="register">create a new account</a></h4>
<form action="${form_target}" method="${form_method}">
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

    "register-template" :
    """
<h1>Create account</h1>
<form action="${form_target}" method="${form_method}$">
    <div class="form-group">
        <label for="username">Username</label>
        <input type="text" class="form-control" id="username" aria-describedby="usernameHelp" placeholder="">
        <small id="usernameHelp" class="form-text text-muted">Max 265 characters</small>
    </div>
    <div class="form-group">
        <label for="password">Password</label>
        <input type="password" class="form-control" id="password" aria-describedby="usernapasswordHelpmeHelp" placeholder="">
        <small id="passwordHelp" class="form-text text-muted">Must be at least 8 and maximum 256 characters</small>
    </div>
    <button type="submit" class="btn btn-primary">Register</button>
</form>
    """,

    "post-template" :
    """
<div class="card">
    <div class="card-body">
        <!--<h4 class="card-title">${post_title}</h4>-->
        <h6 class="card-subtitle mb-2 text-muted">Posted by ${post_author}</h6>
        <p class="card-text">${post_text}</p>
    </div>
</div>
    """,

    "alert-template" :
    """
<div class="alert ${alert_type}" role="alert">
  ${alert_content}
</div>
    """,

    "nav-link-template" :
    """
<li class="nav-item ${nav_active}">
    <a class="nav-link" href="${nav_target}">${nav_text}</a>
</li>
    """
    }