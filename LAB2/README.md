# Сбор и аналитическая обработка информации о сетевом трафике

## Практическое задание №2

### Описание

#### Вы – специалист по информационной безопасности компании “СуперМегатек”.
#### Вы часто используете информацию о сетевом трафике для обнаружения подозрительной и вредоносной активности.  
#### Помогите защитить Вашу компанию от международной хакерской группировки AnonMasons.
#### • Описание полей датасета: timestamp,src,dst,port,bytes
#### • IP адреса внутренней сети начинаются с 12-14
#### • Все остальные IP адреса относятся к внешним узлам

### Задание 2

#### Другой атакующий установил автоматическую задачу в системном планировщике cron для экспорта содержимого внутренней wiki системы.
#### Эта система генерирует большое количество траффика в нерабочие часы, больше чем остальные хосты.
#### Определите IP этой системы. Известно, что ее IP адрес отличается от нарушителя из предыдущей задачи.

### Подключение библиотек

    knitr::opts_chunk$set(echo = TRUE)
    library(arrow)
    library(dplyr)
    library(stringr)
    library(lubridate)
    library(ggplot2)
    
### Загрузка данных

    new_data <- arrow::read_csv_arrow("D:\\ProjectsRstudio\\2_sem_R\\LAB1\\gowiththeflow_20190826.csv",schema=schema(timestamp=int64(),src=utf8(),dst=utf8(),port=int32(),bytes=int32()))
    
## Решение задачи 2

### Предварительная фильтрация

    sel<-filter(new_data, str_detect(src,"^((12|13|14)\\.)"),str_detect(dst,"^((12|13|14)\\.)",negate=TRUE))

    sel$timestampp <- as.POSIXct(sel$timestamp/1000, origin = "1970-01-01")
    sel$hour <- as.numeric(format(sel$timestampp, "%H"))

## Кластерный анализ (фиксация 2-ух ключевых структур использования в рабочие и нерабочие часы

    clust <- 2  
    kmeans_result <- kmeans(matrix(as.numeric(sel$hour), ncol = 1), centers = clust)
    sel$cluster <- as.factor(kmeans_result$cluster)
    centroid <- kmeans_result$centers
    working_hours_cluster <- which.max(centroid)
    working_hours_data <- sel %>%
    filter(cluster == working_hours_cluster)
    start_time <- min(working_hours_data$hour)
    end_time <- max(working_hours_data$hour)

    filter(sel,(hour < start_time | hour > end_time)&str_detect(src,"13.37.84.125",negate=TRUE))%>%
    select(src,bytes)%>%
    group_by(src)%>%
    summarise(bytes=sum(bytes))%>%
    slice_max(bytes)%>%
    select(src)

    ## # A tibble: 1 × 1
    ##   src         
    ##   <chr>       
    ## 1 13.48.72.30				

### Ответ: 13.48.72.30