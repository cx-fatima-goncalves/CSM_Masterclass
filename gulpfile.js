const gulp = require('gulp');
const sass = require('gulp-sass')
const concat = require('gulp-concat');
const minifyCSS = require('gulp-csso');
const uglify = require('gulp-uglify');
const rename = require("gulp-rename");


sass.compiler = require('node-sass');

gulp.task('sass', function () {
  return gulp.src('./public/css/scss/style.scss')
  .pipe(sass().on('error', sass.logError))
  .pipe(minifyCSS())
  .pipe(rename('style.min.css'))
  .pipe(gulp.dest('./public/css/dist'));
});

gulp.task('scripts', function() {
  return gulp.src([
    './public/js/vendor/jquery-3.4.1.min.js',
    './public/js/vendor/bootstrap.min.js',
    './public/js/vendor/swiper.min.js',
    './public/js/scripts.js'
  ])
    .pipe(concat('script.min.js'))
    .pipe(uglify())
    .pipe(gulp.dest('./public/js/dist'))
});

gulp.task('watch:scss', function () {
  gulp.watch('./public/css/scss/**/*.scss', gulp.series('sass'));
});


gulp.task('watch', gulp.parallel('watch:scss'));

gulp.task('default', gulp.parallel('sass', 'scripts'));