-- Insecure schema with sensitive personal data
CREATE TABLE user_profiles (
    id INT PRIMARY KEY AUTO_INCREMENT,
    nic VARCHAR(20) NOT NULL,
    email VARCHAR(100) NOT NULL,
    phone VARCHAR(20),
    health_notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
