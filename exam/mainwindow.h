#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QMap>
#include <QVector>
#include <QFile>
#include "ui_mainwindow.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:


private:
    // QString jsonPath = "D:/Education/Education4/enc/exam/JSON/last_game.json";


    Ui::MainWindow *ui;
    int correctPinCode = 1234;




    int decryptQByteArray(const QByteArray& encryptedBytes, QByteArray& decryptedBytes, unsigned char *key);
    int encryptQByteArray(const QByteArray &plainBytes, QByteArray &encryptedBytes, unsigned char *key);
};

#endif // MAINWINDOW_H
