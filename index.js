require('dotenv').config();

const express = require('express');
const axios = require('axios');
const multer = require('multer');
const FormData = require('form-data');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const API_KEY = process.env.VT_API_KEY;

app.use(express.static('public'));
app.use(express.json());

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir);
}

const upload = multer({ dest: 'uploads/' });

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.get('/results/file/:scanId', async (req, res) => {
    const scanId = req.params.scanId;
    try {
        const response = await axios.get('https://www.virustotal.com/vtapi/v2/file/report', {
            params: {
                apikey: API_KEY,
                resource: scanId
            }
        });

        res.render('result', { 
            scanData: response.data,
            type: 'file',
            id: scanId
        });
    } catch (error) {
        res.status(500).render('result', { 
            scanData: { error: error.message },
            type: 'file',
            id: scanId
        });
    }
});

app.get('/results/url/:encodedUrl', async (req, res) => {
    const encodedUrl = req.params.encodedUrl;
    const url = decodeURIComponent(encodedUrl);

    try {
        const response = await axios.get('https://www.virustotal.com/vtapi/v2/url/report', {
            params: {
                apikey: API_KEY,
                resource: url,
                allinfo: true
            }
        });

        res.render('result', { 
            scanData: response.data,
            type: 'url',
            id: encodedUrl
        });
    } catch (error) {
        res.status(500).render('result', { 
            scanData: { error: error.message },
            type: 'url',
            id: encodedUrl
        });
    }
});

app.get('/results/:type/:id', async (req, res) => {
    if (req.query.check && req.headers['x-requested-with'] === 'XMLHttpRequest') {
        try {
            let response;
            console.log('AJAX kontrolü:', req.params.type, req.params.id);

            if (req.params.type === 'file') {
                response = await axios.get('https://www.virustotal.com/vtapi/v2/file/report', {
                    params: {
                        apikey: API_KEY,
                        resource: req.params.id
                    }
                });
            } else if (req.params.type === 'url') {
                const url = decodeURIComponent(req.params.id);
                response = await axios.get('https://www.virustotal.com/vtapi/v2/url/report', {
                    params: {
                        apikey: API_KEY,
                        resource: url,
                        allinfo: true
                    }
                });
            } else {
                throw new Error('Geçersiz tarama tipi');
            }

            console.log('VirusTotal yanıtı:', response.data);
            return res.json({ 
                success: true,
                scanData: response.data, 
                type: req.params.type, 
                id: req.params.id 
            });
        } catch (error) {
            console.error('AJAX kontrol hatası:', error.message);
            return res.status(500).json({ 
                success: false,
                error: error.message 
            });
        }
    }
});

if (!API_KEY) {
    console.error('HATA: VT_API_KEY tanımlanmamış. Lütfen .env dosyanızı kontrol edin.');
    process.exit(1);
}

app.post('/scan/file', upload.single('file'), async (req, res) => {
    const file = req.file;

    if (!file) {
        console.error('Dosya yükleme hatası: Dosya bulunamadı');
        return res.status(400).json({ error: 'Dosya yüklenmedi' });
    }

    try {
        const formData = new FormData();
        formData.append('file', fs.createReadStream(file.path));
        formData.append('apikey', API_KEY);

        console.log('VirusTotal API\'ye istek gönderiliyor...');
        const response = await axios.post('https://www.virustotal.com/vtapi/v2/file/scan', formData, {
            headers: {
                ...formData.getHeaders()
            }
        });
        console.log('VirusTotal yanıtı:', response.data);

        fs.unlinkSync(file.path);

        res.json({
            scanId: response.data.scan_id,
            type: 'file',
            resultUrl: `/results/file/${response.data.scan_id}`
        });
    } catch (error) {
        console.error('Detaylı hata bilgisi:', {
            message: error.message,
            response: error.response?.data,
            status: error.response?.status
        });
        res.status(500).json({ error: 'Dosya tarama işlemi başarısız: ' + error.message });
    }
});

app.post('/scan/url', async (req, res) => {
    const { url } = req.body;

    if (!url) {
        return res.status(400).json({ error: 'URL girilmedi' });
    }

    try {
        const scanResponse = await axios.post('https://www.virustotal.com/vtapi/v2/url/scan', null, {
            params: {
                apikey: API_KEY,
                url: url
            }
        });

        res.json({
            scanId: scanResponse.data.scan_id,
            type: 'url',
            resultUrl: `/results/url/${encodeURIComponent(url)}`
        });
    } catch (error) {
        console.error('URL tarama hatası:', error.message);
        res.status(500).json({ error: 'URL tarama işlemi başarısız: ' + error.message });
    }
});

app.listen(PORT, () => {
    console.log(`Sunucu port ${PORT} üzerinde çalışıyor`);
});
