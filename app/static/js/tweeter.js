/**
 * attach click handlers to admin interface buttons
 */
window.addEventListener("load", () => {
    document.querySelectorAll(".btn-promote").forEach((el) => {
        el.addEventListener("click", () => {
            let userId = el.getAttribute("data-userid");
            administrationPromotionClickHandler(userId, true);
        });
    });

    document.querySelectorAll(".btn-delete").forEach((el) => {
        el.addEventListener("click", () => {
            let userId = el.getAttribute("data-userid");
            administrationDeletionClickHandler(userId);
        });
    });

    let logoutLink = document.getElementById("logout_link");
    if (logoutLink) {
        logoutLink.addEventListener("click", logoutClickHandler);
    }
    
    let deregisterLink = document.getElementById("deregister_link");
    if (deregisterLink) {
        deregisterLink.addEventListener("click", deregisterClickHandler);
    }
});

/**
 * get CSRF token from html header
 * @returns {string}
 */
function getCSRFToken() {
    return document.querySelector("meta[name='csrf-token']").getAttribute("content");
}

function getPasswordAdminInterface() {
    return document.getElementById("admin_password_input").value;
}

/**
 * 
 * @param {number} userId 
 * @param {boolean} toAdmin 
 * @returns {Promise}
 */
function requestUserPromotion(userId, toAdmin) {
    let body = {
        "is_admin" : toAdmin ? "1" : "0",
        "password" : getPasswordAdminInterface()
    };
    return doRequest(`/users/${userId}`, "PUT", body);
}

/**
 * 
 * @param {number} userId 
 * @returns {Promise}
 */
function requestUserDeletion(userId) {
    let body = {
        "password" : getPasswordAdminInterface()
    };
    return doRequest(`/users/${userId}`, "DELETE", body);
}

/**
 * @returns {Promise}
 */
function requestLogout() {
    return doRequest("/logout", "POST");
}

/**
 * @returns {Promise}
 */
function requestDeregistration() {
    return doRequest("/deregister", "GET");
}

/**
 * 
 * @param {number} userId 
 * @param {boolean} toAdmin 
 */
function administrationPromotionClickHandler(userId, toAdmin) {
    return requestUserPromotion(userId, toAdmin)
        .then(() => {
            document.location.reload();
        });
}

/**
 * 
 * @param {number} userId 
 */
function administrationDeletionClickHandler(userId) {
    return requestUserDeletion(userId)
        .then(() => {
            document.location.reload();
        });
}

/**
 * 
 */
function logoutClickHandler() {
    return requestLogout()
        .then(() => {
            document.location.reload();
        });
}

/**
 * 
 */
function deregisterClickHandler() {
    return requestDeregistration()
        .then(() => {
            document.location.reload();
        });
}

/**
 * 
 * @param {string} url 
 * @param {string} method 
 * @param {Object} body 
 * @returns {Promise}
 */
function doRequest(url, method = "GET", body = {}) {
    body["csrf-token"] = getCSRFToken();

    return fetch(url, {
        credentials : "same-origin",
        method : method,
        headers : {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body : objectToFormData(body)
    })
        .then(status);
}

function status(response) {  
    if (response.status >= 200 && response.status < 300) {  
        return Promise.resolve(response)  
    } else {  
        return Promise.reject(new Error(response.statusText))  
    }  
}

function objectToFormData(o) {
    return Object.entries(o).map((e) => `${encodeURIComponent(e[0])}=${encodeURIComponent(e[1])}`).join("&");
}
  