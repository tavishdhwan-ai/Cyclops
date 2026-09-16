const fs = require('fs');
const path = require('path');

const iconsDir = path.join(__dirname, 'icons');
if (!fs.existsSync(iconsDir)) {
  fs.mkdirSync(iconsDir, { recursive: true });
}

// Helper to construct a minimal valid PNG buffer with a filled color shield-like square/circle
function createPngBuffer(size, r = 16, g = 185, b = 129) { // Sentinel emerald green
  const width = size;
  const height = size;

  // Simple PNG header and chunk builder
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  
  // IHDR chunk
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr.writeUInt8(8, 8); // 8-bit depth
  ihdr.writeUInt8(6, 9); // Truecolor with alpha (RGBA)
  ihdr.writeUInt8(0, 10);
  ihdr.writeUInt8(0, 11);
  ihdr.writeUInt8(0, 12);

  const ihdrChunk = makeChunk('IHDR', ihdr);

  // Raw image data: scanlines with filter byte 0
  const rawData = [];
  const cx = width / 2;
  const cy = height / 2;
  const radius = width * 0.42;

  for (let y = 0; y < height; y++) {
    rawData.push(0); // Filter type 0
    for (let x = 0; x < width; x++) {
      const dx = x - cx;
      const dy = y - cy;
      const isInside = (dx * dx + dy * dy) <= (radius * radius);
      
      if (isInside) {
        // Shield gradient/color
        rawData.push(r, g, b, 255);
      } else {
        rawData.push(0, 0, 0, 0); // Transparent
      }
    }
  }

  const zlib = require('zlib');
  const compressedData = zlib.deflateSync(Buffer.from(rawData));
  const idatChunk = makeChunk('IDAT', compressedData);
  const iendChunk = makeChunk('IEND', Buffer.alloc(0));

  return Buffer.concat([signature, ihdrChunk, idatChunk, iendChunk]);
}

function makeChunk(type, data) {
  const length = data.length;
  const buf = Buffer.alloc(12 + length);
  buf.writeUInt32BE(length, 0);
  buf.write(type, 4, 4, 'ascii');
  data.copy(buf, 8);

  const crc32 = calcCrc32(buf.subarray(4, 8 + length));
  buf.writeUInt32BE(crc32, 8 + length);
  return buf;
}

function calcCrc32(buf) {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    crc ^= buf[i];
    for (let j = 0; j < 8; j++) {
      if (crc & 1) {
        crc = (crc >>> 1) ^ 0xedb88320;
      } else {
        crc = crc >>> 1;
      }
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

[16, 48, 128].forEach(size => {
  const iconBuffer = createPngBuffer(size);
  fs.writeFileSync(path.join(iconsDir, `icon${size}.png`), iconBuffer);
  console.log(`Generated icon${size}.png`);
});

console.log('All extension icons generated successfully.');
