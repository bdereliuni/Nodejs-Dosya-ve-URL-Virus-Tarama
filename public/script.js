document.getElementById('scanFormFile').addEventListener('submit', async function(event) {
    event.preventDefault();
    const file = document.getElementById('fileInput').files[0];
    const resultDiv = document.getElementById('result');

    if (file && file.size > 32 * 1024 * 1024) {
        resultDiv.innerHTML = '<div class="alert alert-danger">Dosya boyutu 32MB\'dan küçük olmalıdır.</div>';
        return;
    }

    if (!file) {
        resultDiv.innerHTML = '<div class="alert alert-danger">Lütfen bir dosya seçin.</div>';
        return;
    }

    let formData = new FormData();
    formData.append('file', file);

    try {
        resultDiv.innerHTML = '<div class="alert alert-info">Dosya taranıyor...</div>';
        
        const response = await fetch('/scan/file', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error('Sunucu yanıt vermedi');
        }

        const data = await response.json();

        if (data.resultUrl) {
            window.location.href = data.resultUrl;
        } else {
            resultDiv.innerHTML = `
                <div class="alert alert-success">
                    <h4>Tarama Sonucu:</h4>
                    <pre>${JSON.stringify(data, null, 2)}</pre>
                </div>`;
        }
    } catch (error) {
        resultDiv.innerHTML = `<div class="alert alert-danger">Hata: ${error.message}</div>`;
    }
});

function isValidUrl(url) {
    try {
        new URL(url);
        return true;
    } catch {
        return false;
    }
}

document.getElementById('scanFormUrl').addEventListener('submit', async function(event) {
    event.preventDefault();
    const url = document.getElementById('urlInput').value.trim();
    const resultDiv = document.getElementById('result');

    if (!isValidUrl(url)) {
        resultDiv.innerHTML = '<div class="alert alert-danger">Geçerli bir URL giriniz.</div>';
        return;
    }

    if (!url) {
        resultDiv.innerHTML = '<div class="alert alert-danger">Lütfen bir URL girin.</div>';
        return;
    }

    try {
        resultDiv.innerHTML = '<div class="alert alert-info">URL taranıyor...</div>';
        
        const response = await fetch('/scan/url', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url })
        });

        if (!response.ok) {
            throw new Error('Sunucu yanıt vermedi');
        }

        const data = await response.json();

        if (data.resultUrl) {
            window.location.href = data.resultUrl;
        } else {
            resultDiv.innerHTML = `
                <div class="alert alert-success">
                    <h4>Tarama Sonucu:</h4>
                    <pre>${JSON.stringify(data, null, 2)}</pre>
                </div>`;
        }
    } catch (error) {
        resultDiv.innerHTML = `<div class="alert alert-danger">Hata: ${error.message}</div>`;
    }
});