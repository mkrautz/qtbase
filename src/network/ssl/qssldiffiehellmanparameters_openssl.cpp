/****************************************************************************
**
** Copyright (C) 2015 Mikkel Krautz <mikkel@krautz.dk>
** Contact: http://www.qt.io/licensing/
**
** This file is part of the QtNetwork module of the Qt Toolkit.
**
** $QT_BEGIN_LICENSE:LGPL21$
** Commercial License Usage
** Licensees holding valid commercial Qt licenses may use this file in
** accordance with the commercial license agreement provided with the
** Software or, alternatively, in accordance with the terms contained in
** a written agreement between you and The Qt Company. For licensing terms
** and conditions see http://www.qt.io/terms-conditions. For further
** information use the contact form at http://www.qt.io/contact-us.
**
** GNU Lesser General Public License Usage
** Alternatively, this file may be used under the terms of the GNU Lesser
** General Public License version 2.1 or version 3 as published by the Free
** Software Foundation and appearing in the file LICENSE.LGPLv21 and
** LICENSE.LGPLv3 included in the packaging of this file. Please review the
** following information to ensure the GNU Lesser General Public License
** requirements will be met: https://www.gnu.org/licenses/lgpl.html and
** http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html.
**
** As a special exception, The Qt Company gives you certain additional
** rights. These rights are described in The Qt Company LGPL Exception
** version 1.1, included in the file LGPL_EXCEPTION.txt in this package.
**
** $QT_END_LICENSE$
**
****************************************************************************/

#include "qssldiffiehellmanparameters.h"
#include "qssldiffiehellmanparameters_p.h"
#include "qsslsocket_openssl_symbols_p.h"
#include "qsslsocket.h"
#include "qsslsocket_p.h"

#include <QtCore/qatomic.h>
#include <QtCore/qbytearray.h>
#include <QtCore/qiodevice.h>
#ifndef QT_NO_DEBUG_STREAM
#include <QtCore/qdebug.h>
#endif

QT_BEGIN_NAMESPACE

static bool isSafeDH(DH *dh)
{
    int status = 0;
    int bad = 0;

    QSslSocketPrivate::ensureInitialized();

    // Mark p < 1024 bits as unsafe.
    if (q_BN_num_bits(dh->p) < 1024) {
        return false;
    }

    if (q_DH_check(dh, &status) != 1)
        return false;

    // From https://wiki.openssl.org/index.php/Diffie-Hellman_parameters:
    //
    //     The additional call to BN_mod_word(dh->p, 24)
    //     (and unmasking of DH_NOT_SUITABLE_GENERATOR)
    //     is performed to ensure your program accepts
    //     IETF group parameters. OpenSSL checks the prime
    //     is congruent to 11 when g = 2; while the IETF's
    //     primes are congruent to 23 when g = 2.
    //     Without the test, the IETF parameters would
    //     fail validation. For details, see Diffie-Hellman
    //     Parameter Check (when g = 2, must p mod 24 == 11?).
    if (q_BN_is_word(dh->g, DH_GENERATOR_2)) {
        long residue = q_BN_mod_word(dh->p, 24);
        if (residue == 11 || residue == 23)
            status &= ~DH_NOT_SUITABLE_GENERATOR;
    }

    bad |= DH_CHECK_P_NOT_PRIME;
    bad |= DH_CHECK_P_NOT_SAFE_PRIME;
    bad |= DH_NOT_SUITABLE_GENERATOR;

    return !(status & bad);
}

void QSslDiffieHellmanParametersPrivate::decodeDer(const QByteArray &der)
{
    if (der.isEmpty()) {
        error = QSslDiffieHellmanParameters::InvalidInputDataError;
        return;
    }

    const unsigned char *data = reinterpret_cast<const unsigned char *>(der.data());
    int len = der.size();

    QSslSocketPrivate::ensureInitialized();

    DH *dh = q_d2i_DHparams(NULL, &data, len);
    if (dh) {
        if (isSafeDH(dh))
            derData = der;
        else
            error =  QSslDiffieHellmanParameters::UnsafeParametersError;
    } else {
        error = QSslDiffieHellmanParameters::InvalidInputDataError;
    }

    q_DH_free(dh);
}

void QSslDiffieHellmanParametersPrivate::decodePem(const QByteArray &pem)
{
    if (pem.isEmpty()) {
        error = QSslDiffieHellmanParameters::InvalidInputDataError;
        return;
    }

    if (!QSslSocket::supportsSsl()) {
        error = QSslDiffieHellmanParameters::InvalidInputDataError;
        return;
    }

    QSslSocketPrivate::ensureInitialized();

    BIO *bio = q_BIO_new_mem_buf(const_cast<char *>(pem.data()), pem.size());
    if (!bio) {
        error = QSslDiffieHellmanParameters::InvalidInputDataError;
        return;
    }

    DH *dh = Q_NULLPTR;
    q_PEM_read_bio_DHparams(bio, &dh, 0, 0);

    if (dh) {
        if (isSafeDH(dh)) {
            char *buf = Q_NULLPTR;
            int len = q_i2d_DHparams(dh, reinterpret_cast<unsigned char **>(&buf));
            if (len > 0)
                derData = QByteArray(buf, len);
            else
                error = QSslDiffieHellmanParameters::InvalidInputDataError;
        } else {
            error = QSslDiffieHellmanParameters::UnsafeParametersError;
        }
    } else {
        error = QSslDiffieHellmanParameters::InvalidInputDataError;
    }

    q_DH_free(dh);
    q_BIO_free(bio);
}

QT_END_NAMESPACE
