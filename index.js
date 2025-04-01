const express = require('express');
const admin = require('firebase-admin');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

admin.initializeApp({
  credential: admin.credential.cert({
    "type": "service_account",
    "project_id": process.env.FIREBASE_PROJECT_ID,
    "private_key_id": process.env.FIREBASE_PRIVATE_KEY_ID,
    "private_key": process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
    "client_email": process.env.FIREBASE_CLIENT_EMAIL,
    "client_id": process.env.FIREBASE_CLIENT_ID,
    "auth_uri": process.env.FIREBASE_AUTH_URI || "https://accounts.google.com/o/oauth2/auth",
    "token_uri": process.env.FIREBASE_TOKEN_URI || "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": process.env.FIREBASE_AUTH_PROVIDER_CERT_URL || "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": process.env.FIREBASE_CLIENT_CERT_URL
  })
});

const db = admin.firestore();
const auth = admin.auth();
const app = express();
const cors = require('cors');
app.use(cors());

app.use(bodyParser.json());

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

let verificationCodes = {};
let resetPasswordCodes = {};

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Correo y contraseña son obligatorios' });
    }

    // Autenticar usuario en Firebase Authentication
    const response = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${process.env.FIREBASE_API_KEY}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, returnSecureToken: true }),
    });

    const data = await response.json();

    if (!response.ok) {
      console.error('Error en el inicio de sesión:', data);
      return res.status(401).json({ error: data.error?.message || 'Correo o contraseña incorrectos' });
    }

    // Obtener el uid del usuario autenticado
    const { localId: uid } = data;

    // Buscar la empresa del usuario en Firestore
    const userRef = admin.firestore().collection('usuarios').doc(uid);
    const userSnap = await userRef.get();

    if (!userSnap.exists) {
      return res.status(404).json({ error: 'No se encontraron datos del usuario' });
    }

    const userData = userSnap.data();

    // Responder con la información del usuario
    res.status(200).json({
      message: 'Inicio de sesión exitoso',
      token: data.idToken,
      email: email,
      empresa: userData.empresa || 'Sin empresa registrada'
    });

  } catch (error) {
    console.error('Error en el servidor:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

app.post('/api/register', async (req, res) => {
  try {
    const { email, password, empresa, numeroEmpleado, rfc } = req.body;

    if (!email || !password || !empresa || !numeroEmpleado || !rfc) {
      return res.status(400).json({ error: 'Todos los campos son obligatorios' });
    }

    const userRecord = await auth.createUser({
      email,
      password,
    });

    await db.collection('usuarios').doc(userRecord.uid).set({
      email,
      empresa,
      numeroEmpleado,
      rfc,
      uid: userRecord.uid,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.status(201).json({ message: 'Usuario registrado exitosamente', uid: userRecord.uid });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/send-verification-code', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Correo electrónico es obligatorio' });
    }

    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();

    verificationCodes[email] = verificationCode;

    const mailOptions = {
      from: `"Alma Sys" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Código de verificación en dos pasos',
      html: `
        <html>
          <head>
            <style>
              body {
                font-family: Arial, sans-serif;
                color: #333;
                padding: 20px;
                background-color: #f4f4f4;
              }
              .verification-code {
                font-size: 24px;
                font-weight: bold;
                color: #FF5722;
                padding: 5px 10px;
                border-radius: 4px;
                background-color: #fff;
                border: 1px solid #FF5722;
              }
              h1 {
                color: #333;
              }
              .footer {
                margin-top: 20px;
                font-size: 12px;
                color: #888;
              }
              .logo {
                width: 100px;
                margin-bottom: 20px;
              }
            </style>
          </head>
          <body>
            <img src="cid:logo@uniqueid" alt="Logo" class="logo"/>
            <h1>Verificación en dos pasos</h1>
            <p>Para completar tu proceso de verificación, ingresa el siguiente código:</p>
            <p class="verification-code">${verificationCode}</p>
            <div class="footer">
              <p>Si no solicitaste este código, por favor ignora este mensaje.</p>
            </div>
          </body>
        </html>
      `,
      attachments: [
        {
          filename: 'alma.png',
          path: './alma.png',
          cid: 'logo@uniqueid'
        }
      ],
    };

    await transporter.sendMail(mailOptions);

    res.status(200).json({ message: 'Código de verificación enviado al correo' });
  } catch (error) {
    console.error('Error al enviar el código:', error);
    res.status(500).json({ error: 'Error al enviar el código' });
  }
});

app.post('/api/verify-code', async (req, res) => {
  try {
    const { email, verificationCode } = req.body;

    if (!email || !verificationCode) {
      return res.status(400).json({ error: 'Correo y código son obligatorios' });
    }

    if (verificationCodes[email] !== verificationCode) {
      return res.status(400).json({ error: 'Código de verificación incorrecto' });
    }

    delete verificationCodes[email];

    res.status(200).json({ message: '¡Verificación exitosa! Redirigiendo a la página principal.' });
  } catch (error) {
    console.error('Error en la verificación:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

app.post('/api/request-reset-password', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Correo electrónico es obligatorio' });
    }

    // Verificar si el correo existe en Firebase
    try {
      await auth.getUserByEmail(email);
    } catch (error) {
      if (error.code === 'auth/user-not-found') {
        // No revelamos si el correo existe o no por seguridad
        return res.status(200).json({ message: 'Si el correo existe, recibirás un código de recuperación' });
      }
      throw error;
    }

    // Generar código de restablecimiento
    const resetCode = Math.floor(100000 + Math.random() * 900000).toString();

    // Almacenar el código con tiempo de expiración (1 hora)
    resetPasswordCodes[email] = {
      code: resetCode,
      expiresAt: Date.now() + 3600000 // 1 hora en milisegundos
    };

    // Enviar correo con el código de restablecimiento
    const mailOptions = {
      from: `"Alma Sys" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Restablecimiento de contraseña',
      html: `
        <html>
          <head>
            <style>
              body {
                font-family: Arial, sans-serif;
                color: #333;
                padding: 20px;
                background-color: #f4f4f4;
              }
              .reset-code {
                font-size: 24px;
                font-weight: bold;
                color: #2196F3;
                padding: 5px 10px;
                border-radius: 4px;
                background-color: #fff;
                border: 1px solid #2196F3;
              }
              h1 {
                color: #333;
              }
              .warning {
                color: #f44336;
                font-weight: bold;
              }
              .footer {
                margin-top: 20px;
                font-size: 12px;
                color: #888;
              }
              .logo {
                width: 100px;
                margin-bottom: 20px;
              }
            </style>
          </head>
          <body>
            <img src="cid:logo@uniqueid" alt="Logo" class="logo"/>
            <h1>Restablecimiento de contraseña</h1>
            <p>Has solicitado restablecer tu contraseña. Utiliza el siguiente código para completar el proceso:</p>
            <p class="reset-code">${resetCode}</p>
            <p>Este código expirará en 1 hora.</p>
            <p class="warning">Si no has solicitado este cambio, te recomendamos cambiar tu contraseña inmediatamente.</p>
            <div class="footer">
              <p>Este es un correo automático, por favor no respondas a este mensaje.</p>
            </div>
          </body>
        </html>
      `,
      attachments: [
        {
          filename: 'alma.png',
          path: './alma.png',
          cid: 'logo@uniqueid'
        }
      ],
    };

    await transporter.sendMail(mailOptions);

    res.status(200).json({ message: 'Código de restablecimiento enviado al correo' });
  } catch (error) {
    console.error('Error al solicitar restablecimiento de contraseña:', error);
    res.status(500).json({ error: 'Error al procesar la solicitud' });
  }
});

app.post('/api/reset-password', async (req, res) => {
  try {
    const { email, verificationCode, newPassword } = req.body;

    if (!email || !verificationCode || !newPassword) {
      return res.status(400).json({ error: 'Todos los campos son obligatorios' });
    }

    // Verificar si existe un código para este correo
    const resetData = resetPasswordCodes[email];
    if (!resetData) {
      return res.status(400).json({ error: 'No hay solicitud de restablecimiento para este correo' });
    }

    // Verificar que el código no haya expirado
    if (Date.now() > resetData.expiresAt) {
      delete resetPasswordCodes[email];
      return res.status(400).json({ error: 'El código ha expirado. Solicita uno nuevo' });
    }

    // Verificar que el código sea correcto
    if (resetData.code !== verificationCode) {
      return res.status(400).json({ error: 'Código de verificación incorrecto' });
    }

    try {
      // Obtener el usuario por correo
      const userRecord = await auth.getUserByEmail(email);

      // Actualizar la contraseña
      await auth.updateUser(userRecord.uid, {
        password: newPassword
      });

      // Eliminar el código usado
      delete resetPasswordCodes[email];

      // Opcional: enviar correo de confirmación
      const mailOptions = {
        from: `"Alma Sys" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: 'Contraseña restablecida con éxito',
        html: `
          <html>
            <head>
              <style>
                body {
                  font-family: Arial, sans-serif;
                  color: #333;
                  padding: 20px;
                  background-color: #f4f4f4;
                }
                h1 {
                  color: #333;
                }
                .success {
                  color: #4CAF50;
                  font-weight: bold;
                }
                .footer {
                  margin-top: 20px;
                  font-size: 12px;
                  color: #888;
                }
                .logo {
                  width: 100px;
                  margin-bottom: 20px;
                }
              </style>
            </head>
            <body>
              <img src="cid:logo@uniqueid" alt="Logo" class="logo"/>
              <h1>Contraseña restablecida</h1>
              <p class="success">Tu contraseña ha sido restablecida con éxito.</p>
              <p>Si no realizaste esta acción, contacta inmediatamente con soporte técnico.</p>
              <div class="footer">
                <p>Este es un correo automático, por favor no respondas a este mensaje.</p>
              </div>
            </body>
          </html>
        `,
        attachments: [
          {
            filename: 'alma.png',
            path: './alma.png',
            cid: 'logo@uniqueid'
          }
        ],
      };

      await transporter.sendMail(mailOptions);

      res.status(200).json({ message: 'Contraseña restablecida con éxito' });
    } catch (error) {
      if (error.code === 'auth/user-not-found') {
        return res.status(400).json({ error: 'Usuario no encontrado' });
      }
      throw error;
    }
  } catch (error) {
    console.error('Error al restablecer contraseña:', error);
    res.status(500).json({ error: 'Error al restablecer la contraseña' });
  }
});

setInterval(() => {
  const now = Date.now();
  for (const email in resetPasswordCodes) {
    if (resetPasswordCodes[email].expiresAt < now) {
      delete resetPasswordCodes[email];
    }
  }
}, 3600000);

app.post('/api/almacenes/nuevo', async (req, res) => {
  try {
    // Extraer el token del encabezado de autorización
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];

    // Verificar el token en Firebase
    const decodedToken = await admin.auth().verifyIdToken(token);
    const uid = decodedToken.uid;

    // Obtener el nombre de la empresa desde Firestore
    const userRef = db.collection('usuarios').doc(uid);
    const userSnap = await userRef.get();

    if (!userSnap.exists) {
      return res.status(404).json({ error: 'No se encontraron datos del usuario' });
    }

    const { empresa } = userSnap.data();

    // Extraer datos del cuerpo de la solicitud
    const {
      nombreAlmacen,
      estado,
      municipio,
      ciudad,
      espacios,
      calle,
      codigoPostal,
      codigo
    } = req.body;

    // Verificar que los campos requeridos no estén vacíos
    if (!nombreAlmacen || !estado || !municipio || !ciudad || !espacios || !calle || !codigoPostal || !codigo) {
      return res.status(400).json({ error: 'Todos los campos son obligatorios' });
    }

    // Crear un nuevo almacén con la empresa asociada
    const nuevoAlmacen = {
      nombreAlmacen,
      estado,
      municipio,
      ciudad,
      espacios,
      calle,
      codigoPostal,
      codigo,
      empresa, // Agregar la empresa
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    };

    // Guardar en Firestore en la colección "almacenes"
    const almacenRef = await db.collection('almacenes').add(nuevoAlmacen);

    // Responder con éxito y el ID generado
    res.status(201).json({ message: 'Almacén creado exitosamente', id: almacenRef.id });

  } catch (error) {
    console.error('Error al crear almacén:', error);
    res.status(500).json({ error: 'Error al procesar la solicitud' });
  }
});

// Ruta para obtener todos los almacenes
app.get('/api/almacenes', async (req, res) => {
  try {
    // Verificar autenticación
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];
    const decodedToken = await admin.auth().verifyIdToken(token);
    const uid = decodedToken.uid;

    // Obtener la empresa del usuario
    const userRef = db.collection('usuarios').doc(uid);
    const userSnap = await userRef.get();

    if (!userSnap.exists) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const { empresa } = userSnap.data();

    // Construir la consulta filtrando por empresa
    let query = db.collection('almacenes').where('empresa', '==', empresa);

    // Aplicar filtros opcionales
    const { estado, activo } = req.query;

    if (estado) {
      query = query.where('estado', '==', estado);
    }

    if (activo !== undefined) {
      query = query.where('activo', '==', activo === 'true');
    }

    // Ejecutar la consulta
    const snapshot = await query.get();
    const almacenes = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));

    res.status(200).json({ almacenes });

  } catch (error) {
    console.error('Error al obtener almacenes:', error);
    res.status(500).json({ error: 'Error al procesar la solicitud' });
  }
});


// Ruta para obtener un almacén específico
app.get('/api/almacenes/:id', async (req, res) => {
  try {
    // Verificar autenticación
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];

    try {
      await admin.auth().verifyIdToken(token);
    } catch (error) {
      return res.status(401).json({ error: 'Token inválido' });
    }

    const almacenId = req.params.id;

    // Obtener el documento
    const almacenDoc = await db.collection('almacenes').doc(almacenId).get();

    if (!almacenDoc.exists) {
      return res.status(404).json({ error: 'Almacén no encontrado' });
    }

    res.status(200).json(almacenDoc.data());

  } catch (error) {
    console.error('Error al obtener almacén:', error);
    res.status(500).json({ error: 'Error al procesar la solicitud' });
  }
});

// Ruta para actualizar un almacén
app.put('/api/almacenes/:id', async (req, res) => {
  try {
    // Verificar autenticación
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];
    let decodedToken;

    try {
      decodedToken = await admin.auth().verifyIdToken(token);
    } catch (error) {
      return res.status(401).json({ error: 'Token inválido' });
    }

    const uid = decodedToken.uid;
    const almacenId = req.params.id;

    // Verificar que el almacén existe
    const almacenDoc = await db.collection('almacenes').doc(almacenId).get();

    if (!almacenDoc.exists) {
      return res.status(404).json({ error: 'Almacén no encontrado' });
    }

    // Obtener datos actualizados
    const {
      nombreAlmacen,
      estado,
      municipio,
      ciudad,
      espacios,
      calle,
      codigoPostal,
      codigo,
      activo
    } = req.body;

    // Crear objeto con datos a actualizar
    const updateData = {};

    if (nombreAlmacen !== undefined) updateData.nombreAlmacen = nombreAlmacen;
    if (estado !== undefined) updateData.estado = estado;
    if (municipio !== undefined) updateData.municipio = municipio;
    if (ciudad !== undefined) updateData.ciudad = ciudad;
    if (espacios !== undefined) updateData.espacios = Number(espacios);
    if (calle !== undefined) updateData.calle = calle;
    if (codigoPostal !== undefined) updateData.codigoPostal = codigoPostal;
    if (codigo !== undefined) updateData.codigo = codigo;
    if (activo !== undefined) updateData.activo = activo;

    // Agregar información de actualización
    updateData.updatedBy = uid;
    updateData.updatedAt = admin.firestore.FieldValue.serverTimestamp();

    // Actualizar el documento
    await db.collection('almacenes').doc(almacenId).update(updateData);

    // Opcional: Registrar la actividad
    await db.collection('actividades').add({
      tipo: 'actualizacion_almacen',
      usuarioId: uid,
      almacenId: almacenId,
      cambios: updateData,
      fecha: admin.firestore.FieldValue.serverTimestamp()
    });

    res.status(200).json({
      message: 'Almacén actualizado exitosamente'
    });

  } catch (error) {
    console.error('Error al actualizar almacén:', error);
    res.status(500).json({ error: 'Error al procesar la solicitud' });
  }
});

// Ruta para eliminar un almacén de la base de datos
app.delete('/api/almacenes/:id', async (req, res) => {
  try {
    // Verificar autenticación
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];
    let decodedToken;

    try {
      decodedToken = await admin.auth().verifyIdToken(token);
    } catch (error) {
      return res.status(401).json({ error: 'Token inválido' });
    }

    const uid = decodedToken.uid;
    const almacenId = req.params.id;

    // Verificar que el almacén existe
    const almacenDoc = await db.collection('almacenes').doc(almacenId).get();

    if (!almacenDoc.exists) {
      return res.status(404).json({ error: 'Almacén no encontrado' });
    }

    // Eliminar el almacén de la base de datos
    await db.collection('almacenes').doc(almacenId).delete();

    // Registrar la actividad de eliminación
    await db.collection('actividades').add({
      tipo: 'eliminacion_almacen',
      usuarioId: uid,
      almacenId: almacenId,
      nombreAlmacen: almacenDoc.data().nombreAlmacen,
      fecha: admin.firestore.FieldValue.serverTimestamp()
    });

    res.status(200).json({
      message: 'Almacén eliminado exitosamente'
    });

  } catch (error) {
    console.error('Error al eliminar almacén:', error);
    res.status(500).json({ error: 'Error al procesar la solicitud' });
  }
});

app.post('/api/productos/nuevo', async (req, res) => {
  try {
    // Extraer el token del encabezado de autorización
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];

    // Verificar el token en Firebase
    const decodedToken = await admin.auth().verifyIdToken(token);
    const uid = decodedToken.uid;

    // Obtener el nombre de la empresa desde Firestore
    const userRef = db.collection('usuarios').doc(uid);
    const userSnap = await userRef.get();

    if (!userSnap.exists) {
      return res.status(404).json({ error: 'No se encontraron datos del usuario' });
    }

    const { empresa } = userSnap.data();

    // Extraer datos del cuerpo de la solicitud
    const {
      nombreProducto,
      categoria,
      precio,
      stock,
      codigoSKU,
      fechaRegistro,
    } = req.body;

    // Verificar que los campos requeridos no estén vacíos
    if (!nombreProducto || !categoria || !precio || !stock || !codigoSKU || !fechaRegistro) {
      return res.status(400).json({ error: 'Todos los campos son obligatorios' });
    }

    // Crear un nuevo producto con la empresa asociada
    const nuevoProducto = {
      nombreProducto,
      categoria,
      precio,
      stock,
      codigoSKU,
      fechaRegistro,
      almacenID: "",  // Atributo vacío de almacenID
      empresa, // Agregar la empresa
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    };

    // Guardar en Firestore en la colección "productos"
    const productoRef = await db.collection('productos').add(nuevoProducto);

    // Responder con éxito y el ID generado
    res.status(201).json({ message: 'Producto creado exitosamente', id: productoRef.id });

  } catch (error) {
    console.error('Error al crear producto:', error);
    res.status(500).json({ error: 'Error al procesar la solicitud' });
  }
});

// Ruta para crear una nueva entrada programada
app.post('/api/programadas/nueva', async (req, res) => {
  try {
    // Extraer el token del encabezado de autorización
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];

    // Verificar el token en Firebase
    const decodedToken = await admin.auth().verifyIdToken(token);
    const uid = decodedToken.uid;

    // Obtener el nombre de la empresa desde Firestore
    const userRef = db.collection('usuarios').doc(uid);
    const userSnap = await userRef.get();

    if (!userSnap.exists) {
      return res.status(404).json({ error: 'No se encontraron datos del usuario' });
    }

    const { empresa } = userSnap.data();

    // Extraer datos del cuerpo de la solicitud
    const {
      fechaRegistro,
      almacen,
      producto,
      descripcion,
      cantidad
    } = req.body;

    // Verificar que los campos requeridos no estén vacíos
    if (!fechaRegistro || !almacen || !producto || !descripcion || !cantidad) {
      return res.status(400).json({ error: 'Todos los campos son obligatorios' });
    }

    // Crear una nueva entrada programada con la empresa asociada
    const nuevaProgramada = {
      fechaRegistro,
      almacen,
      producto,
      descripcion,
      cantidad: Number(cantidad),
      empresa,
      estado: 'pendiente', // Estado inicial
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      createdBy: uid
    };

    // Guardar en Firestore en la colección "programadas"
    const programadaRef = await db.collection('programadas').add(nuevaProgramada);

    // Responder con éxito y el ID generado
    res.status(201).json({ 
      message: 'Entrada programada creada exitosamente', 
      id: programadaRef.id 
    });

  } catch (error) {
    console.error('Error al crear entrada programada:', error);
    res.status(500).json({ error: 'Error al procesar la solicitud' });
  }
});

// Ruta para obtener todas las entradas programadas
app.get('/api/programadas', async (req, res) => {
  try {
    // Verificar autenticación
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];
    const decodedToken = await admin.auth().verifyIdToken(token);
    const uid = decodedToken.uid;

    // Obtener la empresa del usuario
    const userRef = db.collection('usuarios').doc(uid);
    const userSnap = await userRef.get();

    if (!userSnap.exists) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const { empresa } = userSnap.data();

    // Construir la consulta filtrando por empresa
    let query = db.collection('programadas').where('empresa', '==', empresa);

    // Aplicar filtros opcionales
    const { estado, almacen, producto } = req.query;

    if (estado) {
      query = query.where('estado', '==', estado);
    }

    if (almacen) {
      query = query.where('almacen', '==', almacen);
    }

    if (producto) {
      query = query.where('producto', '==', producto);
    }

    // Ejecutar la consulta
    const snapshot = await query.get();
    const programadas = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));

    res.status(200).json({ programadas });

  } catch (error) {
    console.error('Error al obtener entradas programadas:', error);
    res.status(500).json({ error: 'Error al procesar la solicitud' });
  }
});

// Ruta para actualizar una entrada programada
app.put('/api/programadas/:id', async (req, res) => {
  try {
    // Verificar autenticación
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];
    let decodedToken;

    try {
      decodedToken = await admin.auth().verifyIdToken(token);
    } catch (error) {
      return res.status(401).json({ error: 'Token inválido' });
    }

    const uid = decodedToken.uid;
    const programadaId = req.params.id;

    // Verificar que la entrada programada existe
    const programadaDoc = await db.collection('programadas').doc(programadaId).get();

    if (!programadaDoc.exists) {
      return res.status(404).json({ error: 'Entrada programada no encontrada' });
    }

    // Obtener datos actualizados
    const {
      fechaRegistro,
      almacen,
      producto,
      descripcion,
      cantidad,
      estado
    } = req.body;

    // Crear objeto con datos a actualizar
    const updateData = {};

    if (fechaRegistro !== undefined) updateData.fechaRegistro = fechaRegistro;
    if (almacen !== undefined) updateData.almacen = almacen;
    if (producto !== undefined) updateData.producto = producto;
    if (descripcion !== undefined) updateData.descripcion = descripcion;
    if (cantidad !== undefined) updateData.cantidad = Number(cantidad);
    if (estado !== undefined) updateData.estado = estado;

    // Agregar información de actualización
    updateData.updatedBy = uid;
    updateData.updatedAt = admin.firestore.FieldValue.serverTimestamp();

    // Actualizar el documento
    await db.collection('programadas').doc(programadaId).update(updateData);

    res.status(200).json({
      message: 'Entrada programada actualizada exitosamente'
    });

  } catch (error) {
    console.error('Error al actualizar entrada programada:', error);
    res.status(500).json({ error: 'Error al procesar la solicitud' });
  }
});

// Ruta para eliminar una entrada programada
app.delete('/api/programadas/:id', async (req, res) => {
  try {
    // Verificar autenticación
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];
    let decodedToken;

    try {
      decodedToken = await admin.auth().verifyIdToken(token);
    } catch (error) {
      return res.status(401).json({ error: 'Token inválido' });
    }

    const uid = decodedToken.uid;
    const programadaId = req.params.id;

    // Verificar que la entrada programada existe
    const programadaDoc = await db.collection('programadas').doc(programadaId).get();

    if (!programadaDoc.exists) {
      return res.status(404).json({ error: 'Entrada programada no encontrada' });
    }

    // Eliminar la entrada programada
    await db.collection('programadas').doc(programadaId).delete();

    // Registrar la actividad de eliminación
    await db.collection('actividades').add({
      tipo: 'eliminacion_programada',
      usuarioId: uid,
      programadaId: programadaId,
      detalles: programadaDoc.data(),
      fecha: admin.firestore.FieldValue.serverTimestamp()
    });

    res.status(200).json({
      message: 'Entrada programada eliminada exitosamente'
    });

  } catch (error) {
    console.error('Error al eliminar entrada programada:', error);
    res.status(500).json({ error: 'Error al procesar la solicitud' });
  }
});

app.get('/api/productos', async (req, res) => {
  try {
    // Extraer el token del encabezado de autorización
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];

    // Verificar el token en Firebase
    const decodedToken = await admin.auth().verifyIdToken(token);
    const uid = decodedToken.uid;

    // Obtener el nombre de la empresa desde Firestore
    const userRef = db.collection('usuarios').doc(uid);
    const userSnap = await userRef.get();

    if (!userSnap.exists) {
      return res.status(404).json({ error: 'No se encontraron datos del usuario' });
    }

    const { empresa } = userSnap.data();

    // Buscar productos de la empresa en la colección "productos"
    const productosRef = db.collection('productos').where('empresa', '==', empresa);
    const snapshot = await productosRef.get();

    if (snapshot.empty) {
      return res.status(404).json({ error: 'No se encontraron productos' });
    }

    // Crear un arreglo con los productos
    const productos = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
    }));

    res.status(200).json({ productos });

  } catch (error) {
    console.error('Error al obtener productos:', error);
    res.status(500).json({ error: 'Error al procesar la solicitud' });
  }
});

// Ruta para mover un producto entre almacenes
app.post('/api/movimientos/nuevo', async (req, res) => {
  try {
    // Verificar autenticación
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];
    const decodedToken = await admin.auth().verifyIdToken(token);
    const uid = decodedToken.uid;

    // Obtener el nombre de la empresa desde Firestore
    const userRef = db.collection('usuarios').doc(uid);
    const userSnap = await userRef.get();

    if (!userSnap.exists) {
      return res.status(404).json({ error: 'No se encontraron datos del usuario' });
    }

    const { empresa } = userSnap.data();

    // Extraer datos del cuerpo de la solicitud
    const {
      productoId,
      almacenSalida,
      almacenLlegada,
      cantidad,
      fechaRecepcion,
      motivo,
      estatus,
      tipoMovimiento
    } = req.body;

    // Verificar que los campos requeridos no estén vacíos
    if (!productoId || !almacenLlegada || !cantidad || !fechaRecepcion || !estatus) {
      return res.status(400).json({ error: 'Todos los campos son obligatorios' });
    }

    // Asegurar que tipoMovimiento tenga un valor predeterminado si no se envía
    const movimientoTipo = tipoMovimiento || 'entrada';  // Si no se pasa tipoMovimiento, por defecto es 'entrada'

    // Obtener el producto
    const productoDoc = await db.collection('productos').doc(productoId).get();
    
    if (!productoDoc.exists) {
      return res.status(404).json({ error: 'Producto no encontrado' });
    }
    
    const productoData = productoDoc.data();
    
    // Verificar que el producto pertenece a la empresa
    if (productoData.empresa !== empresa) {
      return res.status(403).json({ error: 'No tiene acceso a este producto' });
    }

    // Obtener el nombre de los almacenes
    const almacenSalidaDoc = await db.collection('almacenes').doc(almacenSalida).get();
    const almacenLlegadaDoc = await db.collection('almacenes').doc(almacenLlegada).get();

    if (!almacenSalidaDoc.exists || !almacenLlegadaDoc.exists) {
      return res.status(404).json({ error: 'Almacén no encontrado' });
    }

    const almacenSalidaNombre = almacenSalidaDoc.data().nombreAlmacen;
    const almacenLlegadaNombre = almacenLlegadaDoc.data().nombreAlmacen;

    // Verificar que ambos almacenes pertenezcan a la empresa
    if (almacenSalidaDoc.data().empresa !== empresa || almacenLlegadaDoc.data().empresa !== empresa) {
      return res.status(403).json({ error: 'No tiene acceso a estos almacenes' });
    }

    // Crear un nuevo registro de movimiento
    const nuevoMovimiento = {
      productoId,
      nombreProducto: productoData.nombreProducto,
      almacenOrigen: almacenSalidaNombre,  // Guardar el nombre del almacén de salida
      almacenDestino: almacenLlegadaNombre,  // Guardar el nombre del almacén de llegada
      cantidad: Number(cantidad),
      fechaMovimiento: fechaRecepcion,
      motivo: motivo || 'Traslado de inventario',
      estatus,  // Guardar el estatus del movimiento
      tipoMovimiento: movimientoTipo,  // Guardar el tipo de movimiento (entrada)
      empresa,
      creadoPor: uid,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    };

    // Iniciar una transacción para garantizar la consistencia de los datos
    await db.runTransaction(async (transaction) => {
      // Actualizar el almacén del producto en la colección productos
      transaction.update(db.collection('productos').doc(productoId), {
        almacenID: almacenLlegada,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
      
      // Registrar el movimiento
      const movimientoRef = db.collection('movimientos').doc();
      transaction.set(movimientoRef, nuevoMovimiento);
      
      // Registrar la actividad
      const actividadRef = db.collection('actividades').doc();
      transaction.set(actividadRef, {
        tipo: 'movimiento_producto',
        usuarioId: uid,
        productoId,
        almacenOrigen: almacenSalidaNombre,
        almacenDestino: almacenLlegadaNombre,
        cantidad: Number(cantidad),
        estatus,  // Añadir el estatus a la actividad
        fecha: admin.firestore.FieldValue.serverTimestamp()
      });
    });

    res.status(201).json({ 
      message: 'Producto movido exitosamente'
    });

  } catch (error) {
    console.error('Error al mover producto:', error);
    res.status(500).json({ error: 'Error al procesar la solicitud' });
  }
});


// Ruta para obtener historial de movimientos de un producto
app.get('/api/movimientos', async (req, res) => {
  try {
    // Verificar autenticación
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];
    const decodedToken = await admin.auth().verifyIdToken(token);
    const uid = decodedToken.uid;

    // Obtener el nombre de la empresa desde Firestore
    const userRef = db.collection('usuarios').doc(uid);
    const userSnap = await userRef.get();

    if (!userSnap.exists) {
      return res.status(404).json({ error: 'No se encontraron datos del usuario' });
    }

    const { empresa } = userSnap.data();

    // Construir la consulta filtrando por empresa
    let query = db.collection('movimientos').where('empresa', '==', empresa);

    // Aplicar filtros opcionales
    const { productoId, almacenId, desde, hasta } = req.query;

    if (productoId) {
      query = query.where('productoId', '==', productoId);
    }

    if (almacenId) {
      // Buscar movimientos donde el almacén especificado sea origen o destino
      const movimientosOrigen = await db.collection('movimientos')
        .where('empresa', '==', empresa)
        .where('almacenOrigenId', '==', almacenId)
        .get();
        
      const movimientosDestino = await db.collection('movimientos')
        .where('empresa', '==', empresa)
        .where('almacenDestinoId', '==', almacenId)
        .get();
        
      // Combinar resultados
      const movimientos = [
        ...movimientosOrigen.docs.map(doc => ({ id: doc.id, ...doc.data() })),
        ...movimientosDestino.docs.map(doc => ({ id: doc.id, ...doc.data() }))
      ];
      
      // Eliminar duplicados si los hay
      const movimientosFiltrados = movimientos.filter((movimiento, index, self) =>
        index === self.findIndex((m) => m.id === movimiento.id)
      );
      
      return res.status(200).json({ movimientos: movimientosFiltrados });
    }

    // Si no hay filtro de almacén, continuar con la consulta normal
    const snapshot = await query.orderBy('createdAt', 'desc').get();
    const movimientos = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));

    res.status(200).json({ movimientos });

  } catch (error) {
    console.error('Error al obtener movimientos:', error);
    res.status(500).json({ error: 'Error al procesar la solicitud' });
  }
});


// Ruta para actualizar el estatus de un movimiento
app.put('/api/movimientos/:movimientoId/estatus', async (req, res) => {
  try {
    // Verificar autenticación
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];
    const decodedToken = await admin.auth().verifyIdToken(token);
    const uid = decodedToken.uid;

    // Obtener el nombre de la empresa desde Firestore
    const userRef = db.collection('usuarios').doc(uid);
    const userSnap = await userRef.get();

    if (!userSnap.exists) {
      return res.status(404).json({ error: 'No se encontraron datos del usuario' });
    }

    const { empresa } = userSnap.data();
    const { movimientoId } = req.params;
    const { estatus } = req.body;

    if (!estatus) {
      return res.status(400).json({ error: 'El estatus es requerido' });
    }

    // Referencia al movimiento en Firestore
    const movimientoRef = db.collection('movimientos').doc(movimientoId);
    const movimientoSnap = await movimientoRef.get();

    if (!movimientoSnap.exists) {
      return res.status(404).json({ error: 'Movimiento no encontrado' });
    }

    const movimientoData = movimientoSnap.data();
    if (movimientoData.empresa !== empresa) {
      return res.status(403).json({ error: 'No tienes permiso para modificar este movimiento' });
    }

    // Actualizar el estatus del movimiento
    await movimientoRef.update({ estatus, updatedAt: new Date() });

    res.status(200).json({ message: 'Estatus actualizado correctamente' });
  } catch (error) {
    console.error('Error al actualizar estatus del movimiento:', error);
    res.status(500).json({ error: 'Error al procesar la solicitud' });
  }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});