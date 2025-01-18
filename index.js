const express = require('express');
const fetch = require('node-fetch');  // Importing fetch to make HTTP requests
const bodyParser = require('body-parser');

const API_KEY = '3c7db2bea0841a1693a0fcbe624f6b061d3833f2cff228f129522a91b208081b';  // Replace with your actual API key
const app = express();
const PORT = 8000;

// Middleware to parse JSON body
app.use(bodyParser.json());

// Define the route to get the scan report for a URL
app.post('/api/get-url-report', async (req, res) => {
  const { url } = req.body;
  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  // URL encode the URL to ensure it is safe to use in HTTP requests
  const encodedUrl = encodeURIComponent(url); 
  console.log("Encoded URL:", encodedUrl);  // Log the encoded URL for debugging

  // VirusTotal API endpoint with query parameters
  const apiUrl = `https://www.virustotal.com/vtapi/v2/url/report?apikey=${API_KEY}&resource=${encodedUrl}&allinfo=false&scan=0`;

  const options = {
    method: 'GET',
    headers: {
      accept: 'application/json',
    },
  };

  try {
    // Use fetch to get the scan report from VirusTotal API
    const response = await fetch(apiUrl, options);

    if (!response.ok) {
      // If response is not OK, throw an error
      throw new Error(`HTTP error! Status: ${response.status}`);
    }

    // Parse the JSON response from VirusTotal
    const data = await response.json();

    // Log the response data (optional, for debugging)
    console.log('VirusTotal Response:', data.positives);

    // Send the data as a response to the client
    if(data.positives==0){
        res.json("Link is safe");
    }
    else if(data.positives>0){
        res.json("Link is not safe");
    }
    // res.json(data.positives);

  } catch (error) {
    // Log and handle errors
    console.error('Error:', error.message);
    res.status(500).json({ error: 'Failed to get URL scan report' });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});



// // const express = require("express");
// // const users = require("./MOCK_DATA.json")
// // const API = "3c7db2bea0841a1693a0fcbe624f6b061d3833f2cff228f129522a91b208081b"

// // const app = express();
// // const PORT = 8000;

// // //Routes are define here
// // app.get("/api/users",(req,res)=>{
// //     return res.json(users)
// // })

// // app.get("/check",(req,res)=>{
// //     const options = {method: 'GET', headers: {accept: 'application/json'}};

// //     fetch('https://www.virustotal.com/vtapi/v2/url/feed', options)
// //     .then(res => res.json())
// //     .then(res => console.log(res))
// //     .catch(err => console.error(err));
// // })

// // app.get('/users',(req,res)=>{
// //     const html=`
// //     <ul>
// //     ${users.map((user)=>`<li>${user.first_name},${user.id}</li>`).join(" ")}
// //     </ul>
// //     `;
// //     res.send(html);
// // })

// // app.listen(PORT,()=> console.log(`Server is running in port number:${PORT}`))

// const express = require('express');
// const fetch = require('node-fetch');  // You need to install 'node-fetch' if not already installed
// const bodyParser = require('body-parser'); // Body parser for parsing JSON body

// const API_KEY = '3c7db2bea0841a1693a0fcbe624f6b061d3833f2cff228f129522a91b208081b';
// const app = express();
// const PORT = 8000;

// // Middleware to parse JSON body
// app.use(bodyParser.json());

// // Define the route to scan the URL
// app.post('/api/scan-url', (req, res) => {
//   const { url } = req.body;
//   if (!url) {
//     return res.status(400).json({ error: 'URL is required' });
//   }

//   // Set up the options for the VirusTotal API request
//   const options = {
//     method: 'GET',
//     headers: {
//       'x-apikey': API_KEY
//     }
//   };

//   // Encode URL to base64 (as required by the VirusTotal API)
//   const encodedUrl = Buffer.from(url).toString('base64');
  
//   console.log(encodedUrl)
//   // Make the request to VirusTotal API
//   fetch(`https://www.virustotal.com/api/v3/urls/${encodedUrl}`, options)
//     .then(response => response.json())
//     .then(data => {
//       res.json(data);  // Send the data from VirusTotal API to Postman
//     })
//     .catch(err => {
//       console.error('Error:', err);
//       res.status(500).json({ error: 'Failed to scan URL' });
//     });
// });

// app.listen(PORT, () => {
//   console.log(`Server is running on port ${PORT}`);
// });
