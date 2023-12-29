export const fileFilter = (req: Express.Request, file: Express.Multer.File, callback: Function) => {
    if (!file){
        return callback(new Error('File is empty'), false);
    }

    const fileExtension = file.mimetype.split('/')[1];
    const allowedExtensions = ['jpg', 'jpeg', 'png', 'gif'];

    console.log(fileExtension);

    if (allowedExtensions.includes(fileExtension)){
        return callback(null, true);
    }

    callback(null, false);
}