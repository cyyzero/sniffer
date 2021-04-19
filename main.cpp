#include "mainwindow.h"
#include "sniffer.h"
#include <QApplication>


#include <iostream>
#include <QDebug>
void test();

int main(int argc, char *argv[])
{
    qDebug() << "hello";
//    test();
    QApplication a(argc, argv);

    MainWindow mw;
    mw.show();

    return a.exec();
}
