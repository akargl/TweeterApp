function requestUserPromotion(userId) {
    let url = `/users/${userId}`;

    let body = objectToFormData({
        "is_admin" : "1"
    });

    return fetch(url, {
        credentials : "same-origin",
        method : "PUT",
        headers : {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body : body})
        .then(status);
}

function requestUserDeletion(userId) {
    let url = `/users/${userId}`;

    return fetch(url, { credentials : "same-origin", method : "DELETE"})
        .then(status);
}

function administrationPromotionClickHandler(userId) {
    return requestUserPromotion(userId)
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
  