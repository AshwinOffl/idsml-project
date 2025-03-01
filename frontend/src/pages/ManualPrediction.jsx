import React, { useState } from 'react';
import axios from 'axios';
import CryptoJS from 'crypto-js';  // AES encryption
import JSEncrypt from 'jsencrypt'; // RSA encryption

const ManualPrediction = () => {
  const [formData, setFormData] = useState({
    duration: '',
    protocol_type: '',
    service: '',
    flag: '',
    src_bytes: '',
    dst_bytes: ''
  });

  const [predictionResult, setPredictionResult] = useState(null);
  const [error, setError] = useState(null);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData((prevState) => ({
      ...prevState,
      [name]: value
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      // Generate AES key and encrypt data
      const aesKey = CryptoJS.lib.WordArray.random(16); // 128-bit AES key
      const encryptedFeatures = encryptFeatures(formData, aesKey);

      // Encrypt AES key with RSA (backend public key)
      const encryptedAesKey = await encryptAesKeyWithRsa(aesKey);

      // Send the encrypted data to the backend
      const encryptedData = {
        aes_key: encryptedAesKey,
        nonce: CryptoJS.lib.WordArray.random(12).toString(CryptoJS.enc.Hex), // 96-bit nonce
        ciphertext: encryptedFeatures.ciphertext,
        tag: encryptedFeatures.tag
      };

      const response = await axios.post('/predict', {
        encrypted_features: JSON.stringify(encryptedData)
      });

      // Handle the response and set the prediction result
      setPredictionResult(response.data.prediction);
    } catch (err) {
      setError("Prediction failed. Please try again.");
      console.error(err);
    }
  };

  // Encrypt features using AES
  const encryptFeatures = (features, aesKey) => {
    const plaintext = JSON.stringify(features);
    const encrypted = CryptoJS.AES.encrypt(plaintext, aesKey).toString();
    return {
      ciphertext: encrypted,
      tag: "dummy-tag"  // You can compute a tag if needed, depending on your encryption setup
    };
  };

  // Encrypt AES key using RSA
  const encryptAesKeyWithRsa = (aesKey) => {
    return new Promise((resolve, reject) => {
      const publicKey = `-----BEGIN PUBLIC KEY-----
      YOUR_BACKEND_PUBLIC_KEY_HERE
      -----END PUBLIC KEY-----`;

      const encrypt = new JSEncrypt();
      encrypt.setPublicKey(publicKey);

      const aesKeyBase64 = aesKey.toString(CryptoJS.enc.Base64);
      const encryptedAesKey = encrypt.encrypt(aesKeyBase64);

      if (encryptedAesKey) {
        resolve(encryptedAesKey);
      } else {
        reject("Error encrypting AES key");
      }
    });
  };

  return (
    <div className="manual-prediction-container">
      <h2>Manual Prediction</h2>
      <form onSubmit={handleSubmit}>
        <div>
          <label>Duration:</label>
          <input
            type="number"
            name="duration"
            value={formData.duration}
            onChange={handleInputChange}
            required
          />
        </div>
        <div>
          <label>Protocol Type:</label>
          <input
            type="text"
            name="protocol_type"
            value={formData.protocol_type}
            onChange={handleInputChange}
            required
          />
        </div>
        <div>
          <label>Service:</label>
          <input
            type="text"
            name="service"
            value={formData.service}
            onChange={handleInputChange}
            required
          />
        </div>
        <div>
          <label>Flag:</label>
          <input
            type="text"
            name="flag"
            value={formData.flag}
            onChange={handleInputChange}
            required
          />
        </div>
        <div>
          <label>Source Bytes:</label>
          <input
            type="number"
            name="src_bytes"
            value={formData.src_bytes}
            onChange={handleInputChange}
            required
          />
        </div>
        <div>
          <label>Destination Bytes:</label>
          <input
            type="number"
            name="dst_bytes"
            value={formData.dst_bytes}
            onChange={handleInputChange}
            required
          />
        </div>
        <button type="submit">Predict</button>
      </form>

      {predictionResult && (
        <div>
          <h3>Prediction Result: {predictionResult}</h3>
        </div>
      )}

      {error && <p style={{ color: 'red' }}>{error}</p>}
    </div>
  );
};

export default ManualPrediction;
