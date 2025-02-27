DROP TABLE IF EXISTS users;

CREATE TABLE users(
 id INT AUTO_INCREMENT PRIMARY KEY,
 username VARCHAR(255) UNIQUE NOT NULL,
 email VARCHAR(255) UNIQUE NOT NULL,
 password VARCHAR(255) NOT NULL
 
 );

 INSERT INTO users
  (username,email,password)
VALUES
  ('temwani','temwaninkowani@gmail.com','qwerty');

DROP TABLE IF EXISTS posts;

CREATE TABLE tasks (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    status ENUM ('pending','completed') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

