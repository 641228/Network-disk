<script>
    const express = require('express');
    const cors = require('cors');
    const bcrypt = require('bcrypt');
    const jwt = require('jsonwebtoken');
    const multer = require('multer');
    const fs = require('fs');
    const path = require('path');
    
    // 初始化Express应用
    const app = express();
    const PORT = process.env.PORT || 3000;
    const JWT_SECRET = 'your-secret-key'; // 实际使用时应更换为更安全的密钥
    
    // 确保必要的目录存在
    const USERS_DIR = path.join(__dirname, 'users');
    const UPLOADS_DIR = path.join(__dirname, 'uploads');
    if (!fs.existsSync(USERS_DIR)) fs.mkdirSync(USERS_DIR);
    if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR);
    
    // 中间件
    app.use(cors());
    app.use(express.json());
    app.use(express.static('public'));
    
    // 用户认证中间件
    const authenticateToken = (req, res, next) => {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        
        if (!token) return res.status(401).json({ message: '需要认证' });
        
        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (err) return res.status(403).json({ message: '无效的令牌' });
            req.user = user;
            next();
        });
    };
    
    // 存储配置
    const storage = multer.diskStorage({
        destination: (req, file, cb) => {
            const userDir = path.join(UPLOADS_DIR, req.user.id);
            if (!fs.existsSync(userDir)) {
                fs.mkdirSync(userDir, { recursive: true });
            }
            cb(null, userDir);
        },
        filename: (req, file, cb) => {
            cb(null, Date.now() + '-' + file.originalname);
        }
    });
    
    const upload = multer({ storage: storage });
    
    // 路由 - 注册
    app.post('/api/register', async (req, res) => {
        try {
            const { username, password } = req.body;
            const userId = Date.now().toString();
            const hashedPassword = await bcrypt.hash(password, 10);
            
            // 保存用户信息
            const userData = { id: userId, username, password: hashedPassword };
            fs.writeFileSync(path.join(USERS_DIR, `${userId}.json`), JSON.stringify(userData));
            
            res.status(201).json({ message: '注册成功' });
        } catch (error) {
            res.status(500).json({ message: '注册失败', error: error.message });
        }
    });
    
    // 路由 - 登录
    app.post('/api/login', async (req, res) => {
        try {
            const { username, password } = req.body;
            
            // 查找用户
            const userFiles = fs.readdirSync(USERS_DIR);
            let userData = null;
            
            for (const file of userFiles) {
                const data = JSON.parse(fs.readFileSync(path.join(USERS_DIR, file), 'utf8'));
                if (data.username === username) {
                    userData = data;
                    break;
                }
            }
            
            if (!userData) {
                return res.status(401).json({ message: '用户名或密码错误' });
            }
            
            // 验证密码
            const validPassword = await bcrypt.compare(password, userData.password);
            if (!validPassword) {
                return res.status(401).json({ message: '用户名或密码错误' });
            }
            
            // 生成JWT令牌
            const token = jwt.sign(
                { id: userData.id, username: userData.username },
                JWT_SECRET,
                { expiresIn: '24h' }
            );
            
            res.json({ token, user: { id: userData.id, username: userData.username } });
        } catch (error) {
            res.status(500).json({ message: '登录失败', error: error.message });
        }
    });
    
    // 路由 - 上传文件
    app.post('/api/upload', authenticateToken, upload.single('file'), (req, res) => {
        if (!req.file) {
            return res.status(400).json({ message: '请选择文件' });
        }
        
        res.json({ 
            message: '文件上传成功', 
            file: {
                name: req.file.originalname,
                path: req.file.filename,
                size: req.file.size,
                uploadedAt: new Date()
            }
        });
    });
    
    // 路由 - 获取文件列表
    app.get('/api/files', authenticateToken, (req, res) => {
        try {
            const userDir = path.join(UPLOADS_DIR, req.user.id);
            if (!fs.existsSync(userDir)) {
                return res.json({ files: [] });
            }
            
            const files = fs.readdirSync(userDir).map(filename => {
                const stats = fs.statSync(path.join(userDir, filename));
                const originalName = filename.split('-').slice(1).join('-');
                
                return {
                    id: filename,
                    name: originalName,
                    size: stats.size,
                    uploadedAt: stats.ctime
                };
            });
            
            res.json({ files });
        } catch (error) {
            res.status(500).json({ message: '获取文件列表失败', error: error.message });
        }
    });
    
    // 路由 - 下载文件
    app.get('/api/files/:fileId', authenticateToken, (req, res) => {
        try {
            const fileId = req.params.fileId;
            const userDir = path.join(UPLOADS_DIR, req.user.id);
            const filePath = path.join(userDir, fileId);
            
            if (!fs.existsSync(filePath)) {
                return res.status(404).json({ message: '文件不存在' });
            }
            
            const originalName = fileId.split('-').slice(1).join('-');
            res.download(filePath, originalName);
        } catch (error) {
            res.status(500).json({ message: '下载文件失败', error: error.message });
        }
    });
    
    // 路由 - 删除文件
    app.delete('/api/files/:fileId', authenticateToken, (req, res) => {
        try {
            const fileId = req.params.fileId;
            const userDir = path.join(UPLOADS_DIR, req.user.id);
            const filePath = path.join(userDir, fileId);
            
            if (!fs.existsSync(filePath)) {
                return res.status(404).json({ message: '文件不存在' });
            }
            
            fs.unlinkSync(filePath);
            res.json({ message: '文件删除成功' });
        } catch (error) {
            res.status(500).json({ message: '删除文件失败', error: error.message });
        }
    });
    
    // 提供前端页面
    app.get('/', (req, res) => {
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
    });
    
    // 启动服务器
    app.listen(PORT, () => {
        console.log(`服务器运行在 http://localhost:${PORT}`);
    });
        
</script>