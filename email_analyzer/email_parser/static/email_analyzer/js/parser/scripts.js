function showSpinner() {
    document.getElementById('spinner').style.display = 'block';
}

function hideSpinner() {
    document.getElementById('spinner').style.display = 'none';
}

document.addEventListener('DOMContentLoaded', function () {
    showSpinner();
    setTimeout(() => {
        hideSpinner();
        document.getElementById('results').innerHTML = '<h2>Analysis Complete</h2>';
    }, 3000);
});

