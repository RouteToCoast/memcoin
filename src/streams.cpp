// Copyright (c) 2025 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <streams.h>

#include <array>
#include <cstdio>
#include <limits>


/* -- CAutoFile -- */

CAutoFile::CAutoFile(FILE *filenew, int nTypeIn, int nVersionIn) : nType(nTypeIn), nVersion(nVersionIn), file(filenew) {}

CAutoFile::CAutoFile(CAutoFile &&o) : nType(o.nType), nVersion(o.nVersion), file(o.file) { o.setNull(); }

CAutoFile &CAutoFile::operator=(CAutoFile &&o) {
    if (this != &o) {
        if (file != o.file) fclose(); // close our managed file if we have one and it's not same as o's
        file = o.file;
        nType = o.nType;
        nVersion = o.nVersion;
        o.setNull(); // null out moved-from object to complete the transfer
    }
    return *this;
}

CAutoFile::~CAutoFile() { fclose(); }

void CAutoFile::setNull() {
    nType = nVersion = 0;
    file = nullptr;
}

void CAutoFile::fclose() {
    if (file) {
        std::fclose(file);
        file = nullptr;
    }
}

FILE *CAutoFile::release() {
    FILE *ret = file;
    file = nullptr;
    return ret;
}

size_t CAutoFile::detail_fread(std::span<std::byte> dst) {
    if (!file) {
        throw std::ios_base::failure("CAutoFile::read: file handle is nullptr");
    }
    return std::fread(dst.data(), 1, dst.size(), file);
}

void CAutoFile::read(std::span<std::byte> buf) {
    if (detail_fread(buf) != buf.size()) {
        throw std::ios_base::failure(std::feof(file) ? "CAutoFile::read: end of file"
                                                     : "CAutoFile::read: fread failed");
    }
}

void CAutoFile::ignore(size_t nSize) {
    if (!file) {
        throw std::ios_base::failure("CAutoFile::ignore: file handle is nullptr");
    }
    std::array<std::byte, 4096> buf;
    while (nSize > 0) {
        const size_t nNow = std::min(nSize, buf.size());
        if (std::fread(buf.data(), 1, nNow, file) != nNow) {
            throw std::ios_base::failure(std::feof(file) ? "CAutoFile::ignore: end of file"
                                                         : "CAutoFile::read: fread failed");
        }
        nSize -= nNow;
    }
}

void CAutoFile::write(std::span<const std::byte> buf) {
    if (!file) {
        throw std::ios_base::failure("CAutoFile::write: file handle is nullptr");
    }
    if (std::fwrite(buf.data(), 1, buf.size(), file) != buf.size()) {
        throw std::ios_base::failure("CAutoFile::write: write failed");
    }
}


/* -- CBufferedFile -- */

bool CBufferedFile::Fill() {
    size_t pos = nSrcPos % byteBuf.size();
    size_t readNow = byteBuf.size() - pos;
    size_t nAvail = byteBuf.size() - (nSrcPos - nReadPos) - nRewind;
    if (nAvail < readNow) {
        readNow = nAvail;
    }
    if (readNow == 0) {
        return false;
    }
    size_t nBytes = std::fread(&byteBuf[pos], 1, readNow, src);
    if (nBytes == 0) {
        throw std::ios_base::failure(std::feof(src) ? "CBufferedFile::Fill: end of file"
                                                    : "CBufferedFile::Fill: fread failed");
    } else {
        nSrcPos += nBytes;
        return true;
    }
}

CBufferedFile::CBufferedFile(FILE *fileIn, uint64_t nBufSize, uint64_t nRewindIn, int nTypeIn, int nVersionIn)
    : nType(nTypeIn), nVersion(nVersionIn), src{fileIn}, nSrcPos(0), nReadPos(0),
      nReadLimit(std::numeric_limits<uint64_t>::max()), nRewind(nRewindIn), byteBuf(nBufSize, std::byte{}) {}

CBufferedFile::~CBufferedFile() { fclose(); }

void CBufferedFile::fclose() {
    if (src) {
        std::fclose(src);
        src = nullptr;
    }
}

void CBufferedFile::read(std::span<std::byte> outBuf) {
    if (outBuf.size() + nReadPos > nReadLimit) {
        throw std::ios_base::failure("Read attempted past buffer limit");
    }
    if (outBuf.size() + nRewind > byteBuf.size()) {
        throw std::ios_base::failure("Read larger than buffer size");
    }
    while (!outBuf.empty()) {
        if (nReadPos == nSrcPos) {
            Fill();
        }
        const size_t pos = nReadPos % byteBuf.size();
        size_t nNow = outBuf.size();
        if (nNow + pos > byteBuf.size()) {
            nNow = byteBuf.size() - pos;
        }
        if (nNow + nReadPos > nSrcPos) {
            nNow = nSrcPos - nReadPos;
        }
        std::memcpy(outBuf.data(), &byteBuf[pos], nNow);
        nReadPos += nNow;
        outBuf = outBuf.subspan(nNow);
    }
}

bool CBufferedFile::SetPos(uint64_t nPos) {
    nReadPos = nPos;
    if (nReadPos + nRewind < nSrcPos) {
        nReadPos = nSrcPos - nRewind;
        return false;
    } else if (nReadPos > nSrcPos) {
        nReadPos = nSrcPos;
        return false;
    } else {
        return true;
    }
}

bool CBufferedFile::Seek(uint64_t nPos) {
    long nLongPos = nPos;
    if (nPos != static_cast<uint64_t>(nLongPos)) {
        return false;
    }
    if (std::fseek(src, nLongPos, SEEK_SET)) {
        return false;
    }
    nLongPos = std::ftell(src);
    nSrcPos = nLongPos;
    nReadPos = nLongPos;
    return true;
}

bool CBufferedFile::SetLimit(uint64_t nPos) {
    if (nPos < nReadPos) {
        return false;
    }
    nReadLimit = nPos;
    return true;
}

void CBufferedFile::FindByte(const std::byte ch) {
    while (true) {
        if (nReadPos == nSrcPos) {
            Fill();
        }
        if (byteBuf[nReadPos % byteBuf.size()] == ch) {
            break;
        }
        nReadPos++;
    }
}
