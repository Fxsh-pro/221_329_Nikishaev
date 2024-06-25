#include "mainwindow.h"
#include <QRandomGenerator>
#include <QMessageBox>
#include <QBuffer>
#include <QCryptographicHash>
#include <QFile>
#include <QJsonObject>
#include <QJsonDocument>
#include <QJsonArray>

#include <openssl/evp.h>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow) {

    ui->setupUi(this);
    ui->stackedWidget->setCurrentWidget(ui->mainPage);

    connect(ui->uploadFileButton, &QPushButton::clicked, this, &MainWindow::openFile);
    loadPincode();
    qDebug() << "PINCODE  " + pincode;
    loadTransactions();
}

MainWindow::~MainWindow() {
    delete ui;
}

void MainWindow::loadPincode() {
    QString pincodeFilePath = "D:/educ-2c2s-cryptographic/exam/pincode.txt";
    QFile file(pincodeFilePath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Error", "Could not open pincode file");
        return;
    }

    QTextStream in(&file);
    if (!in.atEnd()) {
        pincode = in.readLine().trimmed();
    } else {
        QMessageBox::critical(this, "Error", "Pincode file is empty");
    }

    file.close();
}


QByteArray MainWindow::calculateHash(const Transaction &transaction, const QByteArray &previousHash) {
    QString concatenatedString = transaction.amount + transaction.walletNumber + transaction.date + QString(previousHash.toHex());
    QByteArray data = concatenatedString.toUtf8();
    auto hash = QCryptographicHash::hash(data, QCryptographicHash::Sha256);
    QString readableHash = QString::fromUtf8(hash.toHex());
    qDebug() << "transaction:" << concatenatedString;
    qDebug() << "previousHash:" << previousHash.toHex();
    qDebug() << "Hash for transaction:" << readableHash;
    return hash;
}

void MainWindow::displayTransactions(const QVector<Transaction> &transactions) {
    QByteArray previousHash;
    bool hashMismatch = false;

    ui->transactionsList->clear();

    QString headerText = "Сумма, Номер кошелька, Дата, Хэш\n";

    QTextCursor cursor(ui->transactionsList->textCursor());
    cursor.movePosition(QTextCursor::End);
    QTextCharFormat headerFormat;
    cursor.insertText(headerText, headerFormat);

    for (const Transaction &transaction : transactions) {
        QByteArray calculatedHash = calculateHash(transaction, previousHash);
        bool hashesMatch = (calculatedHash == transaction.hash);

        QString displayText = QString("%1, %2, %3, %4\n")
                                  .arg(transaction.amount, transaction.walletNumber, transaction.date, transaction.hash.toHex());

        QTextCharFormat format;
        if (!hashesMatch || hashMismatch) {
            format.setForeground(Qt::red);
            hashMismatch = true;
        }

        cursor.insertText(displayText, format);

        previousHash = transaction.hash;
    }
}


void MainWindow::openFile() {
    //QString fileName = QFileDialog::getOpenFileName(this, tr("Открыть файл"), QString(), tr("CSV Files (*.csv);;Text Files (*.txt)"));
    QString fileName = QFileDialog::getOpenFileName(this, tr("Открыть файл"), QString(), tr("Text Files (*.txt)"));

    // if (!fileName.isEmpty()) {
    //     filePath = fileName;
    //     loadTransactions();
    // }
    if (!fileName.isEmpty()) {
        decryptAndDisplayFile(fileName);
    }
}

void MainWindow::decryptAndDisplayFile(const QString &fileName)
{
    QByteArray encryptedData = readFileData(fileName);
    if (encryptedData.isEmpty()) {
        return;
    }

    QByteArray decryptedData;

    QByteArray hash = QCryptographicHash::hash(pincode.toUtf8(), QCryptographicHash::Sha256);
    unsigned char hash_key[32] = {0};
    memcpy(hash_key, hash.data(), 32);

    QString readableHash = QString::fromUtf8(hash.toHex());
    qDebug() << pincode + " " + readableHash << " " << hash_key;

    int decryptResult = decryptQByteArray(encryptedData, decryptedData, hash_key);
    if (decryptResult != 0) {
        QMessageBox::critical(this, "Error", "Decryption failed");
        return;
    }

    qDebug() << "decryptedData " + decryptedData;
}

QByteArray MainWindow::readFileData(const QString &fileName)
{
    QFile file(fileName);
    if (!file.open(QIODevice::ReadOnly)) {
        QMessageBox::critical(this, "Error", "Could not open file: " + file.errorString());
        return QByteArray();
    }

    QByteArray data = file.readAll();
    file.close();
    return data;
}


void MainWindow::loadTransactions() {
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Error", "Could not open transactions file");
        return;
    }

    QTextStream in(&file);
    QVector<Transaction> transactions;
    while (!in.atEnd()) {
        QString line = in.readLine();
        QStringList fields = line.split(',');

        if (fields.size() != 4) {
            continue;
        }

        Transaction transaction;
        transaction.amount = fields[0];
        transaction.walletNumber = fields[1];
        transaction.date = fields[2];
        transaction.hash = QByteArray::fromHex(fields[3].toUtf8());

        transactions.append(transaction);
    }

    displayTransactions(transactions);
}


int MainWindow::decryptQByteArray(const QByteArray& encryptedBytes, QByteArray& decryptedBytes, unsigned char *key)
{
    qDebug() << "Decrypting";
    QByteArray iv_hex("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f");
    QByteArray iv_ba = QByteArray::fromHex(iv_hex);

    unsigned char iv[16] = {0};
    memcpy(iv, iv_ba.data(), 16);

    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if (!EVP_DecryptInit_ex2(ctx, EVP_aes_256_cbc(), key, iv, NULL)) {
        qDebug() << "Error";
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    #define BUF_LEN 256
    unsigned char encrypted_buf[BUF_LEN] = {0}, decrypted_buf[BUF_LEN] = {0};
    int encr_len, decr_len;

    QDataStream encrypted_stream(encryptedBytes);

    decryptedBytes.clear();
    QBuffer decryptedBuffer(&decryptedBytes);
    decryptedBuffer.open(QIODevice::ReadWrite);


    encr_len = encrypted_stream.readRawData(reinterpret_cast<char*>(encrypted_buf), BUF_LEN);
    while(encr_len > 0){

        if (!EVP_DecryptUpdate(ctx, decrypted_buf, &decr_len, encrypted_buf, encr_len)) {
            /* Error */
            qDebug() << "Error";
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }

        decryptedBuffer.write(reinterpret_cast<char*>(decrypted_buf), decr_len);
        encr_len = encrypted_stream.readRawData(reinterpret_cast<char*>(encrypted_buf), BUF_LEN);
    }

    int tmplen;
    if (!EVP_DecryptFinal_ex(ctx, decrypted_buf, &tmplen)) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    decryptedBuffer.write(reinterpret_cast<char*>(decrypted_buf), tmplen);
    EVP_CIPHER_CTX_free(ctx);

    decryptedBuffer.close();
    return 0;
}

int MainWindow::encryptQByteArray(const QByteArray &plainBytes, QByteArray &encryptedBytes, unsigned char *key)
{
    qDebug() << "Encrypting";

    QByteArray iv_hex("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f");
    QByteArray iv_ba = QByteArray::fromHex(iv_hex);
    unsigned char iv[16] = {0};
    memcpy(iv, iv_ba.data(), 16);

    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv)) {
        qDebug() << "Error: EVP_EncryptInit_ex";
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    #define BUF_LEN 256
    unsigned char encrypted_buf[BUF_LEN] = {0}, plain_buf[BUF_LEN] = {0};
    int encr_len, plain_len;

    QDataStream plain_stream(plainBytes);

    encryptedBytes.clear();
    QBuffer encryptedBuffer(&encryptedBytes);
    encryptedBuffer.open(QIODevice::ReadWrite);

    plain_len = plain_stream.readRawData(reinterpret_cast<char*>(plain_buf), BUF_LEN);
    while (plain_len > 0) {
        if (!EVP_EncryptUpdate(ctx, encrypted_buf, &encr_len, plain_buf, plain_len)) {
            qDebug() << "Error: EVP_EncryptUpdate";
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }

        encryptedBuffer.write(reinterpret_cast<char*>(encrypted_buf), encr_len);
        plain_len = plain_stream.readRawData(reinterpret_cast<char*>(plain_buf), BUF_LEN);
    }

    int tmplen;
    if (!EVP_EncryptFinal_ex(ctx, encrypted_buf, &tmplen)) {
        qDebug() << "Error: EVP_EncryptFinal_ex";
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    encryptedBuffer.write(reinterpret_cast<char*>(encrypted_buf), tmplen);
    EVP_CIPHER_CTX_free(ctx);

    encryptedBuffer.close();
    return 0;
}
