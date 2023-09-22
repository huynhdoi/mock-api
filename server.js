const fs = require('fs')
const bodyParser = require('body-parser')
const jsonServer = require('json-server')
const jwt = require('jsonwebtoken')

const server = jsonServer.create()
const router = jsonServer.router('./db.json')
const db = JSON.parse(fs.readFileSync('./db.json', 'UTF-8'))
const exnternalUsersDB = JSON.parse(fs.readFileSync('./external-users.json', 'UTF-8'))
const innternalUsersDB = JSON.parse(fs.readFileSync('./internal-users.json', 'UTF-8'))

server.use(bodyParser.urlencoded({ extended: true }))
server.use(bodyParser.json({ limit: '50mb' }))
server.use(jsonServer.defaults());

const SECRET_KEY = '123456789'

const expiresIn = '1h'
const bcrypt = require('bcrypt');

// Create a token from a payload 
function createToken(payload) {
  return jwt.sign(payload, SECRET_KEY, { expiresIn })
}

// Verify the token internal-users
function verifyToken(token) {
  return jwt.verify(token, SECRET_KEY, (err, decode) => decode !== undefined ? decode : err)
}

// Check if the user exists in database
async function isAuthenticatedExternalUser({ email, password }) {
  const findUser = exnternalUsersDB.users.find(user => (user.email === email && user.isDeactivate === false)) 
  const isTheSame  =  await bcrypt.compare(password, findUser.password);
   return  isTheSame && findUser?.id;
}
// Check if the user exists in database
async function isAuthenticatedIternalUser({ email, password }) {
  const findUser = innternalUsersDB.users.find(user => (user.email === email && user.isDeactivate === false)) 
  const isTheSame  =  await bcrypt.compare(password, findUser.password);
  
   return  isTheSame && findUser?.id;
}
// Check if the email exists in database
function isAuthenticatedEmail({ email }) {
  return exnternalUsersDB.users.findIndex(user => user.email === email) !== -1
}
// Hàm băm mật khẩu và lưu vào cơ sở dữ liệu
function hashPassword(password) {
  const saltRounds = 10;
  return bcrypt.hash(password, saltRounds);
}

/* _____________internal user api___________ */
server.post('/auth/admin-login', async (req, res) => {
  console.log("login endpoint called; request body:");
  console.log(req.body);
  const { email, password } = req.body;
  if (await isAuthenticatedIternalUser({ email, password }) === false) {
    const status = 400
    const message = 'Tên đăng nhật hoặc Mật khẩu chưa đúng'
    res.status(status).json({ status, message })
    return
  }
  const access_token = createToken({ email, password })
  console.log("Access Token:" + access_token);
  const userIfo = innternalUsersDB.users.find(async (user) => user.email === email);
  console.log(userIfo);
  res.status(200).json({
    accessToken: access_token,
    ...userIfo
  })
})

server.get('/internal-user', (req, res) => {
  console.log("GET all users endpoint called");

  fs.readFile("./internal-users.json", (err, data) => {
    if (err) {
      const status = 500;
      const message = "Failed to read user data";
      res.status(status).json({ status, message });
      return;
    }

    try {
      const usersData = JSON.parse(data.toString());
      if (!usersData || !usersData.users || !Array.isArray(usersData.users)) {
        const status = 500;
        const message = "Invalid user data format";
        res.status(status).json({ status, message });
        return;
      }

      const users = usersData.users;
      res.status(200).json(users);
    } catch (error) {
      const status = 500;
      const message = "Error parsing user data";
      res.status(status).json({ status, message });
    }
  });
});

server.get('/internal-user/:id', (req, res) => {
  const userId = parseInt(req.params.id); // Lấy ID từ đường dẫn (URL)
  console.log(`GET by ID endpoint called for user with ID: ${userId}`);

  fs.readFile("./internal-users.json", (err, data) => {
    if (err) {
      const status = 401;
      const message = err;
      res.status(status).json({ status, message });
      return;
    }

    const usersData = JSON.parse(data.toString());
    const user = usersData.users.find(u => u.id === userId); // Tìm người dùng theo ID
    console.log(`user with ID: ${user}`);

    if (user) {
      res.status(200).json(user);
    } else {
      const status = 404;
      const message = `User with ID ${userId} not found`;
      res.status(status).json({ status, message });
    }
  });
});
server.post('/internal-user', (req, res) => {
  console.log("POST create user endpoint called; request body:");
  console.log(req.body);

  const { email, password, userName, role, isDeactivate } = req.body;

  fs.readFile("./internal-users.json", async (err, data) => {
    if (err) {
      const status = 401;
      const message = err;
      res.status(status).json({ status, message });
      return;
    }

    try {
      const usersData = JSON.parse(data.toString());
      if (!usersData || !usersData.users || !Array.isArray(usersData.users)) {
        const status = 500;
        const message = "Invalid user data format";
        res.status(status).json({ status, message });
        return;
      }

      const users = usersData.users;
      const hashedPassword = await hashPassword(password);
      // Tạo một người dùng mới với dữ liệu từ yêu cầu
      const newUser = {
        id: users.length + 1, // Tạo một ID mới dựa trên số lượng người dùng hiện có
        email,
        password: hashedPassword,
        userName,
        role,
        isDeactivate,
      };

      // Thêm người dùng mới vào danh sách người dùng
      users.push(newUser);

      // Lưu danh sách người dùng đã cập nhật vào tệp JSON
      fs.writeFile("./internal-users.json", JSON.stringify(usersData), (err) => {
        if (err) {
          const status = 500;
          const message = "Failed to update user data";
          res.status(status).json({ status, message });
        } else {
          const status = 201; // Mã trạng thái 201: Created
          const message = "User created successfully";
          res.status(status).json({ status, message, user: newUser });
        }
      });
    } catch (error) {
      const status = 500;
      const message = "Error parsing user data";
      res.status(status).json({ status, message });
    }
  });
});
server.put('/internal-user/:id', (req, res) => {
  const userId = parseInt(req.params.id);
  console.log(`PUT update user endpoint called for user with ID: ${userId}`);

  const { email, password, userName, role, isDeactivate } = req.body;

  fs.readFile("./internal-users.json", (err, data) => {
    if (err) {
      const status = 401;
      const message = err;
      res.status(status).json({ status, message });
      return;
    }

    try {
      const usersData = JSON.parse(data.toString());
      if (!usersData || !usersData.users || !Array.isArray(usersData.users)) {
        const status = 500;
        const message = "Invalid user data format";
        res.status(status).json({ status, message });
        return;
      }

      const users = usersData.users;
      const userIndex = users.findIndex(u => u.id === userId);

      if (userIndex !== -1) {
        // Cập nhật thông tin người dùng
        users[userIndex] = { id: userId, email, password, userName, role, isDeactivate };

        // Lưu danh sách người dùng đã cập nhật vào tệp JSON
        fs.writeFile("./internal-users.json", JSON.stringify(usersData), (err) => {
          if (err) {
            const status = 500;
            const message = "Failed to update user data";
            res.status(status).json({ status, message });
          } else {
            const status = 200;
            const message = `User with ID ${userId} has been updated`;
            res.status(status).json({ status, message });
          }
        });
      } else {
        const status = 404;
        const message = `User with ID ${userId} not found`;
        res.status(status).json({ status, message });
      }
    } catch (error) {
      const status = 500;
      const message = "Error parsing user data";
      res.status(status).json({ status, message });
    }
  });
});
server.put('/internal-user/update-status/:id', (req, res) => {
  const userId = parseInt(req.params.id);
  console.log(`PUT update status user endpoint called for user with ID: ${userId}`);

  fs.readFile("./internal-users.json", (err, data) => {
    if (err) {
      const status = 401;
      const message = err;
      res.status(status).json({ status, message });
      return;
    }

    try {
      const usersData = JSON.parse(data.toString());
      if (!usersData || !usersData.users || !Array.isArray(usersData.users)) {
        const status = 500;
        const message = "Invalid user data format";
        res.status(status).json({ status, message });
        return;
      }

      const users = usersData.users;
      const userIndex = users.findIndex(u => u.id === userId);

      if (userIndex !== -1) {
        // Cập nhật thông tin người dùng
        const { email, password, userName, role, isDeactivate } = users[userIndex];
        users[userIndex] = { id: userId, email, password, userName, role, isDeactivate: !isDeactivate };

        // Lưu danh sách người dùng đã cập nhật vào tệp JSON
        fs.writeFile("./internal-users.json", JSON.stringify(usersData), (err) => {
          if (err) {
            const status = 500;
            const message = "Failed to update user data";
            res.status(status).json({ status, message });
          } else {
            const status = 200;
            const message = `User with ID ${userId} has been updated`;
            res.status(status).json({ status, message });
          }
        });
      } else {
        const status = 404;
        const message = `User with ID ${userId} not found`;
        res.status(status).json({ status, message });
      }
    } catch (error) {
      const status = 500;
      const message = "Error parsing user data";
      res.status(status).json({ status, message });
    }
  });
});
server.delete('/internal-user/:id', (req, res) => {
  const userId = parseInt(req.params.id); // Lấy ID từ đường dẫn (URL)
  console.log(`DELETE endpoint called for user with ID: ${userId}`);

  fs.readFile("./internal-users.json", (err, data) => {
    if (err) {
      const status = 401;
      const message = err;
      res.status(status).json({ status, message });
      return;
    }

    let users = JSON.parse(data.toString()).users;
    const userIndex = users.findIndex(u => u.id === userId); // Tìm chỉ mục của người dùng có ID tương ứng

    if (userIndex !== -1) {
      // Nếu tìm thấy người dùng, xóa người dùng khỏi danh sách
      users.splice(userIndex, 1);

      // Lưu danh sách người dùng đã cập nhật vào tệp JSON
      fs.writeFile("./internal-users.json", JSON.stringify({ users }), (err) => {
        if (err) {
          const status = 500;
          const message = "Failed to update user data";
          res.status(status).json({ status, message });
        } else {
          const status = 200;
          const message = `User with ID ${userId} has been deleted`;
          res.status(status).json({ status, message });
        }
      });
    } else {
      const status = 404;
      const message = `User with ID ${userId} not found`;
      res.status(status).json({ status, message });
    }
  });
});



/* _____________user customer api___________ */
server.get('/external-user', (req, res) => {
  console.log("GET all users endpoint called");

  fs.readFile("./external-users.json", (err, data) => {
    if (err) {
      const status = 500;
      const message = "Failed to read user data";
      res.status(status).json({ status, message });
      return;
    }

    try {
      const usersData = JSON.parse(data.toString());
      if (!usersData || !usersData.users || !Array.isArray(usersData.users)) {
        const status = 500;
        const message = "Invalid user data format";
        res.status(status).json({ status, message });
        return;
      }

      const users = usersData.users;
      res.status(200).json(users);
    } catch (error) {
      const status = 500;
      const message = "Error parsing user data";
      res.status(status).json({ status, message });
    }
  });
});
server.get('/external-user/:id', (req, res) => {
  const userId = parseInt(req.params.id); // Lấy ID từ đường dẫn (URL)
  console.log(`GET by ID endpoint called for user with ID: ${userId}`);

  fs.readFile("./external-users.json", (err, data) => {
    if (err) {
      const status = 401;
      const message = err;
      res.status(status).json({ status, message });
      return;
    }

    const usersData = JSON.parse(data.toString());
    const user = usersData.users.find(u => u.id === userId); // Tìm người dùng theo ID
    console.log(`user with ID: ${user}`);

    if (user) {
      res.status(200).json(user);
    } else {
      const status = 404;
      const message = `User with ID ${userId} not found`;
      res.status(status).json({ status, message });
    }
  });
});
server.post('/external-user', (req, res) => {
  console.log("POST create user endpoint called; request body:");
  console.log(req.body);

  const { email, password, userName, point, isDeactivate } = req.body;

  fs.readFile("./external-users.json", async (err, data) => {
    if (err) {
      const status = 404;
      const message = err;
      res.status(status).json({ status, message });
      return;
    }

    try {
      const usersData = JSON.parse(data.toString());
      if (!usersData || !usersData.users || !Array.isArray(usersData.users)) {
        const status = 500;
        const message = "Invalid user data format";
        res.status(status).json({ status, message });
        return;
      }

      const users = usersData.users;
      const hashedPassword = await hashPassword(password);
      // Tạo một người dùng mới với dữ liệu từ yêu cầu
      const newUser = {
        id: users.length + 1, // Tạo một ID mới dựa trên số lượng người dùng hiện có
        email,
        password: hashedPassword,
        userName,
        point,
        isDeactivate
      };

      // Thêm người dùng mới vào danh sách người dùng
      users.push(newUser);

      // Lưu danh sách người dùng đã cập nhật vào tệp JSON
      fs.writeFile("./external-users.json", JSON.stringify(usersData), (err) => {
        if (err) {
          const status = 500;
          const message = "Failed to update user data";
          res.status(status).json({ status, message });
        } else {
          const status = 201; // Mã trạng thái 201: Created
          const message = "User created successfully";
          res.status(status).json({ status, message, user: newUser });
        }
      });
    } catch (error) {
      const status = 500;
      const message = "Error parsing user data";
      res.status(status).json({ status, message });
    }
  });
});
server.put('/external-user/:id', (req, res) => {
  const userId = parseInt(req.params.id);
  console.log(`PUT update user endpoint called for user with ID: ${userId}`);

  const { email, password, userName, point, isDeactivate } = req.body;

  fs.readFile("./external-users.json", (err, data) => {
    if (err) {
      const status = 401;
      const message = err;
      res.status(status).json({ status, message });
      return;
    }

    try {
      const usersData = JSON.parse(data.toString());
      if (!usersData || !usersData.users || !Array.isArray(usersData.users)) {
        const status = 500;
        const message = "Invalid user data format";
        res.status(status).json({ status, message });
        return;
      }

      const users = usersData.users;
      const userIndex = users.findIndex(u => u.id === userId);

      if (userIndex !== -1) {
        // Cập nhật thông tin người dùng
        users[userIndex] = { id: userId, email, password, userName, point, isDeactivate };

        // Lưu danh sách người dùng đã cập nhật vào tệp JSON
        fs.writeFile("./users.json", JSON.stringify(usersData), (err) => {
          if (err) {
            const status = 500;
            const message = "Failed to update user data";
            res.status(status).json({ status, message });
          } else {
            const status = 200;
            const message = `User with ID ${userId} has been updated`;
            res.status(status).json({ status, message });
          }
        });
      } else {
        const status = 404;
        const message = `User with ID ${userId} not found`;
        res.status(status).json({ status, message });
      }
    } catch (error) {
      const status = 500;
      const message = "Error parsing user data";
      res.status(status).json({ status, message });
    }
  });
});
server.put('/external-user/update-status/:id', (req, res) => {
  const userId = parseInt(req.params.id);
  console.log(`PUT update user endpoint called for user with ID: ${userId}`);

  fs.readFile("./external-users.json", (err, data) => {
    if (err) {
      const status = 401;
      const message = err;
      res.status(status).json({ status, message });
      return;
    }

    try {
      const usersData = JSON.parse(data.toString());
      if (!usersData || !usersData.users || !Array.isArray(usersData.users)) {
        const status = 500;
        const message = "Invalid user data format";
        res.status(status).json({ status, message });
        return;
      }

      const users = usersData.users;
      const userIndex = users.findIndex(u => u.id === userId);

      if (userIndex !== -1) {
        // Cập nhật thông tin người dùng
        const { email, password, userName, point, isDeactivate } = users[userIndex];
        const updateItem = { id: userId, email, password, userName, point, isDeactivate: !isDeactivate };
        users[userIndex] = updateItem;
        console.log(updateItem);

        // Lưu danh sách người dùng đã cập nhật vào tệp JSON
        fs.writeFile("./external-users.json", JSON.stringify(usersData), (err) => {
          if (err) {
            const status = 500;
            const message = "Failed to update user data";
            res.status(status).json({ status, message });
          } else {
            const status = 200;
            const message = `User with ID ${userId} has been updated`;
            res.status(status).json({ status, message });
          }
        });
      } else {
        const status = 404;
        const message = `User with ID ${userId} not found`;
        res.status(status).json({ status, message });
      }
    } catch (error) {
      const status = 500;
      const message = "Error parsing user data";
      res.status(status).json({ status, message });
    }
  });
});
server.delete('/external-user/:id', (req, res) => {
  const userId = parseInt(req.params.id); // Lấy ID từ đường dẫn (URL)
  console.log(`DELETE endpoint called for user with ID: ${userId}`);

  fs.readFile("./external-users.json", (err, data) => {
    if (err) {
      const status = 401;
      const message = err;
      res.status(status).json({ status, message });
      return;
    }

    let users = JSON.parse(data.toString()).users;
    const userIndex = users.findIndex(u => u.id === userId); // Tìm chỉ mục của người dùng có ID tương ứng

    if (userIndex !== -1) {
      // Nếu tìm thấy người dùng, xóa người dùng khỏi danh sách
      users.splice(userIndex, 1);

      // Lưu danh sách người dùng đã cập nhật vào tệp JSON
      fs.writeFile("./external-users.json", JSON.stringify({ users }), (err) => {
        if (err) {
          const status = 500;
          const message = "Failed to update user data";
          res.status(status).json({ status, message });
        } else {
          const status = 200;
          const message = `User with ID ${userId} has been deleted`;
          res.status(status).json({ status, message });
        }
      });
    } else {
      const status = 404;
      const message = `User with ID ${userId} not found`;
      res.status(status).json({ status, message });
    }
  });
});

/* external user login */
server.post('/auth/login', async (req, res) => {
  console.log("login endpoint called; request body:");
  console.log(req.body);
  const { email, password } = req.body;
  if (await isAuthenticatedExternalUser({ email, password }) === false) {
    const status = 400
    const message = 'Tên đăng nhật hoặc Mật khẩu chưa đúng'
    res.status(status).json({ status, message })
    return
  }
  const access_token = createToken({ email, password })
  console.log("Access Token:" + access_token);
  const userIfo = exnternalUsersDB.users.find(async user => user.email === email);
  console.log(userIfo);
  res.status(200).json({
    accessToken: access_token,
    ...userIfo
  })
})

server.post('/auth/email', (req, res) => {
  console.log("login endpoint called; request body:");
  console.log(req.body);
  const { email } = req.body;
  if (isAuthenticatedEmail({ email }) === false) {
    const status = 400
    const message = 'Tài khoản với địa chỉ email này không tồn tại'
    res.status(status).json({ status, message })
    return
  }

  res.status(200).json({
    email,
  })
})


/* _____________Gifts api___________ */
// server.get('/gifts', (req, res) => {
//   console.log("GET all Gift endpoint called");

//   fs.readFile("./db.json", (err, data) => {
//     if (err) {
//       const status = 500;
//       const message = "Failed to read Gift data";
//       res.status(status).json({ status, message });
//       return;
//     }

//     try {
//       const usersData = JSON.parse(data.toString());
//       if (!usersData || !usersData.users || !Array.isArray(usersData.users)) {
//         const status = 500;
//         const message = "Invalid Gift data format";
//         res.status(status).json({ status, message });
//         return;
//       }

//       const users = usersData.users;
//       res.status(200).json(users);
//     } catch (error) {
//       const status = 500;
//       const message = "Error parsing user data";
//       res.status(status).json({ status, message });
//     }
//   });
// });
// server.get('/gifts/:id', (req, res) => {
//   const userId = parseInt(req.params.id); // Lấy ID từ đường dẫn (URL)
//   console.log(`GET by ID endpoint called for Gift with ID: ${userId}`);

//   fs.readFile("./db.json", (err, data) => {
//     if (err) {
//       const status = 401;
//       const message = err;
//       res.status(status).json({ status, message });
//       return;
//     }

//     const usersData = JSON.parse(data.toString());
//     const user = usersData.users.find(u => u.id === userId); // Tìm Gift theo ID
//     console.log(`Gift with ID: ${user}`);

//     if (user) {
//       res.status(200).json(user);
//     } else {
//       const status = 404;
//       const message = `User with ID ${userId} not found`;
//       res.status(status).json({ status, message });
//     }
//   });
// });
// server.post('/gifts', (req, res) => {
//   console.log("POST create Gift endpoint called; request body:");
//   console.log(req.body);

//   const { email, password, userName, point } = req.body;

//   fs.readFile("./db.json", (err, data) => {
//     if (err) {
//       const status = 404;
//       const message = err;
//       res.status(status).json({ status, message });
//       return;
//     }

//     try {
//       const usersData = JSON.parse(data.toString());
//       if (!usersData || !usersData.users || !Array.isArray(usersData.users)) {
//         const status = 500;
//         const message = "Invalid Gift data format";
//         res.status(status).json({ status, message });
//         return;
//       }

//       const users = usersData.users;

//       // Tạo một người dùng mới với dữ liệu từ yêu cầu
//       const newUser = {
//         id: users.length + 1, // Tạo một ID mới dựa trên số lượng người dùng hiện có
//         email,
//         password,
//         userName,
//         point,
//       };

//       // Thêm người dùng mới vào danh sách người dùng
//       users.push(newUser);

//       // Lưu danh sách người dùng đã cập nhật vào tệp JSON
//       fs.writeFile("./external-users.json", JSON.stringify(usersData), (err) => {
//         if (err) {
//           const status = 500;
//           const message = "Failed to update Gift data";
//           res.status(status).json({ status, message });
//         } else {
//           const status = 201; // Mã trạng thái 201: Created
//           const message = "Gift created successfully";
//           res.status(status).json({ status, message, user: newUser });
//         }
//       });
//     } catch (error) {
//       const status = 500;
//       const message = "Error parsing Gift data";
//       res.status(status).json({ status, message });
//     }
//   });
// });
// server.put('/gifts/:id', (req, res) => {
//   const userId = parseInt(req.params.id);
//   console.log(`PUT update Gift endpoint called for Gift with ID: ${userId}`);

//   const { email, password, userName, point } = req.body;

//   fs.readFile("./db.json", (err, data) => {
//     if (err) {
//       const status = 401;
//       const message = err;
//       res.status(status).json({ status, message });
//       return;
//     }

//     try {
//       const usersData = JSON.parse(data.toString());
//       if (!usersData || !usersData.users || !Array.isArray(usersData.users)) {
//         const status = 500;
//         const message = "Invalid Gift data format";
//         res.status(status).json({ status, message });
//         return;
//       }

//       const users = usersData.users;
//       const userIndex = users.findIndex(u => u.id === userId);

//       if (userIndex !== -1) {
//         // Cập nhật thông tin Gift
//         users[userIndex] = { id: userId, email, password, userName, point };

//         // Lưu danh sách Giftđã cập nhật vào tệp JSON
//         fs.writeFile("./db.json", JSON.stringify(usersData), (err) => {
//           if (err) {
//             const status = 500;
//             const message = "Failed to update user data";
//             res.status(status).json({ status, message });
//           } else {
//             const status = 200;
//             const message = `Gift with ID ${userId} has been updated`;
//             res.status(status).json({ status, message });
//           }
//         });
//       } else {
//         const status = 404;
//         const message = `Gift with ID ${userId} not found`;
//         res.status(status).json({ status, message });
//       }
//     } catch (error) {
//       const status = 500;
//       const message = "Error parsing user data";
//       res.status(status).json({ status, message });
//     }
//   });
// });
// server.delete('/gifts/:id', (req, res) => {
//   const userId = parseInt(req.params.id); // Lấy ID từ đường dẫn (URL)
//   console.log(`DELETE endpoint called for user with ID: ${userId}`);

//   fs.readFile("./db.json", (err, data) => {
//     if (err) {
//       const status = 401;
//       const message = err;
//       res.status(status).json({ status, message });
//       return;
//     }

//     let users = JSON.parse(data.toString()).users;
//     const userIndex = users.findIndex(u => u.id === userId); // Tìm chỉ mục của Gift có ID tương ứng

//     if (userIndex !== -1) {
//       users.splice(userIndex, 1);

//       // Lưu danh sách người dùng đã cập nhật vào tệp JSON
//       fs.writeFile("./db.json", JSON.stringify({ users }), (err) => {
//         if (err) {
//           const status = 500;
//           const message = "Failed to update user data";
//           res.status(status).json({ status, message });
//         } else {
//           const status = 200;
//           const message = `Gift with ID ${userId} has been deleted`;
//           res.status(status).json({ status, message });
//         }
//       });
//     } else {
//       const status = 404;
//       const message = `Gift with ID ${userId} not found`;
//       res.status(status).json({ status, message });
//     }
//   });
// });

// gifts to one of the users from ./db.json
server.post('/gifts-hot/list', (req, res) => {
  console.log("gifts hot endpoint called; request body:");
  console.log(req.body);
  const { point, check } = req.body;
  if (check) {
    const giftsHot = db.gifts.filter(item => item.hotWeek == check);
    res.status(200).json(
      giftsHot
    )
  } else {
    res.status(200).json(
      []
    )
  }
})

// gifts to one of the users from ./db.json
server.post('/gifts-exchanged/list', (req, res) => {
  console.log("gifts hot endpoint called; request body:");
  console.log(req.body);

  const { point, check } = req.body;
  if (check) {
    const giftsExchanged = db.gifts.filter(item => item.point <= point);
    res.status(200).json(
      giftsExchanged
    )
  } else {
    res.status(200).json([]);
  }

})
// gifts to one of the users from ./db.json
server.post('/gifts-almost-exchanged/list', (req, res) => {
  console.log("gifts hot endpoint called; request body:");
  console.log(req.body);
  const { point, check } = req.body;

  if (check) {
    const giftsAlmostExchanged = db.gifts.filter(item => point > item.point && item.point <= (point + (point / 5)));
    res.status(200).json(
      giftsAlmostExchanged
    )
  } else {
    res.status(200).json([]);
  }

})

server.use(/^(?!\/(auth|contact|gifts-hot)).*$/, (req, res, next) => {
  if (req.headers.ID == undefined && req.headers.authorization == undefined || req.headers.authorization.split(' ')[0] !== 'Bearer') {
    const status = 401
    const message = 'Error in authorization format'
    res.status(status).json({ status, message })
    return
  }

  try {
    let verifyTokenResult;
    verifyTokenResult = verifyToken(req.headers.authorization.split(' ')[1]);

    if (verifyTokenResult instanceof Error) {
      const status = 401
      const message = 'Access token not provided'
      res.status(status).json({ status, message })
      return
    }
    next()
  } catch (err) {
    const status = 401
    const message = 'Error access_token is revoked'
    res.status(status).json({ status, message })
  }
})

server.use(router)

server.listen(8000, () => {
  console.log('Run Auth API Server')
})