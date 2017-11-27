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
});

/**
 * get CSRF token from html header
 * @returns {string}
 */
function getCSRFToken() {
    return document.querySelector("meta[name='csrf-token']").getAttribute("content");
}

/**
 * 
 * @param {number} userId 
 * @param {boolean} toAdmin 
 */
function requestUserPromotion(userId, toAdmin) {
    let url = `/users/${userId}`;

    let body = objectToFormData({
        "is_admin" : toAdmin ? "1" : "0",
        "csrf-token" : getCSRFToken(),
    });

    return fetch(url, {
        credentials : "same-origin",
        method : "PUT",
        headers : {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body : body
    })
        .then(status);
}

/**
 * 
 * @param {number} userId 
 */
function requestUserDeletion(userId) {
    let url = `/users/${userId}`;

    let body = objectToFormData({
        "csrf-token" : getCSRFToken(),
    });

    return fetch(url, {
        credentials : "same-origin",
        method : "DELETE",
        headers : {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body : body
    })
        .then(status);
}

function administrationPromotionClickHandler(userId, toAdmin) {
    return requestUserPromotion(userId, toAdmin)
        .then(() => {
            document.location.reload();
        });
}

function administrationDeletionClickHandler(userId) {
    return requestUserDeletion(userId)
        .then(() => {
            document.location.reload();
        });
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
  